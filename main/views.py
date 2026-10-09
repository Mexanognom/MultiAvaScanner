"""HTTP views — thin layer over services."""

import logging
import os
import tempfile

import requests
from django.http import JsonResponse
from django.shortcuts import render
from django.views import View

from .ai_screenshot import analyze_screenshot_with_gemini
from .exceptions import VTRateLimitError
from .helpers import build_response, error_response, get_client_ip, get_file_sha256
from .models import ScanResult, ScreenshotScan
from .rate_limit import rate_limit
from .services import ScanService
from .utils import check_pwned_password

logger = logging.getLogger(__name__)


class HomeView(View):
    def get(self, request):
        recent = ScanResult.objects.filter(status="done").order_by("-created_at")[:10]
        return render(request, "main/index.html", {"recent": recent})


class HistoryView(View):
    def get(self, request):
        scans = ScanResult.objects.filter(status="done").order_by("-created_at")[:50]
        return render(request, "main/history.html", {"scans": scans})


class ScanDetailView(View):
    def get(self, request, scan_id):
        try:
            scan = ScanResult.objects.get(id=scan_id)
        except ScanResult.DoesNotExist:
            return error_response("Не найдено", status=404)
        return JsonResponse(build_response(scan))


class ScanURLView(View):
    @rate_limit(max_requests=8, window=60, key_prefix="scan_url")
    def post(self, request):
        url = request.POST.get("url", "").strip()
        if not url:
            return error_response("URL не указан")

        try:
            service = ScanService()
            scan = service.scan_url(url, user_ip=get_client_ip(request))
        except VTRateLimitError as e:
            return error_response(str(e), status=429)
        except requests.RequestException:
            logger.exception("VT request failed for URL: %s", url)
            return error_response("Не удалось связаться с VirusTotal. Попробуйте позже.", status=502)

        if scan.status == "error":
            return error_response("Анализ занял слишком долго. Попробуйте ещё раз.", status=504)

        return JsonResponse(build_response(scan))


class ScanFileView(View):
    MAX_SIZE = 32 * 1024 * 1024  # 32 MB

    @rate_limit(max_requests=5, window=60, key_prefix="scan_file")
    def post(self, request):
        uploaded = request.FILES.get("file")

        if not uploaded:
            return error_response("Файл не загружен")
        if not uploaded.name.endswith(".apk"):
            return error_response("Разрешены только .apk файлы")
        if uploaded.size > self.MAX_SIZE:
            return error_response("Файл слишком большой (макс. 32MB)")

        file_bytes = uploaded.read()

        try:
            service = ScanService()
            scan = service.scan_apk(
                filename=uploaded.name,
                file_bytes=file_bytes,
                user_ip=get_client_ip(request),
            )
        except VTRateLimitError as e:
            return error_response(str(e), status=429)
        except requests.RequestException:
            logger.exception("VT request failed for APK: %s", uploaded.name)
            return error_response("Не удалось связаться с VirusTotal. Попробуйте позже.", status=502)

        if scan.status == "error":
            return error_response("Анализ занял слишком долго. Попробуйте ещё раз.", status=504)

        return JsonResponse(build_response(scan))


class ScanQRView(View):
    @rate_limit(max_requests=8, window=60, key_prefix="scan_qr")
    def post(self, request):
        file = request.FILES.get("qr")

        if not file:
            return error_response("Файл не загружен")
        if not file.content_type or not file.content_type.startswith("image/"):
            return error_response("Нужен файл изображения")

        try:
            service = ScanService()
            scan, decoded = service.scan_qr(file, user_ip=get_client_ip(request))
        except VTRateLimitError as e:
            return error_response(str(e), status=429)
        except requests.RequestException:
            logger.exception("VT request failed for QR")
            return error_response("Не удалось связаться с VirusTotal. Попробуйте позже.", status=502)
        except Exception as e:
            logger.exception("QR scan failed")
            return error_response(str(e), status=500)

        if scan is None:
            return error_response("QR не распознан")

        if scan.status == "error":
            return error_response("Анализ занял слишком долго. Попробуйте ещё раз.", status=504)

        # QR is not a URL
        if scan.raw_result and "decoded" in scan.raw_result and not scan.url:
            return JsonResponse({
                "id": scan.id,
                "scan_type": "qr",
                "status": "done",
                "decoded": decoded,
                "message": "QR код распознан, но это не ссылка",
            })

        data = build_response(scan)
        data["decoded"] = decoded
        return JsonResponse(data)


class ScanPasswordView(View):
    @rate_limit(max_requests=15, window=60, key_prefix="scan_password")
    def post(self, request):
        password = request.POST.get("password", "").strip()
        if not password:
            return error_response("Пароль не указан")

        try:
            result = check_pwned_password(password)
        except requests.RequestException as e:
            logger.exception("HIBP request failed")
            return error_response(f"Ошибка запроса: {e}", status=500)

        pwned = result["pwned"]
        count = result["count"]

        if pwned:
            verdict = "dangerous"
            title = "Этот пароль небезопасен"
            message = f"Пароль найден в утечках {count} раз"
            recommendation = (
                "Этот пароль уже использовался в утечках данных и считается небезопасным. "
                "Рекомендуем срочно изменить его.\n"
                "Используйте длинный пароль (12–16+ символов), добавьте заглавные буквы, "
                "цифры и специальные символы.\n"
                "Нажмите кнопку ниже, чтобы сгенерировать надёжный пароль."
            )
        else:
            verdict = "clean"
            title = "Пароль не найден в утечках"
            message = "Пароль не найден в известных базах утечек."
            recommendation = (
                "Это хороший знак, но не гарантия полной безопасности.\n"
                "Рекомендуется использовать уникальный пароль длиной не менее 12–16 символов, "
                "с буквами, цифрами и специальными символами.\n"
                "Вы можете сгенерировать более надёжный пароль ниже."
            )

        masked = password[:2] + "*" * max(len(password) - 2, 0)

        return JsonResponse({
            "status": "done",
            "scan_type": "password",
            "verdict": verdict,
            "title": title,
            "message": message,
            "recommendation": recommendation,
            "pwned": pwned,
            "count": count,
            "danger_percent": 100 if pwned else 15,
            "malicious": 1 if pwned else 0,
            "suspicious": 0,
            "harmless": 0 if pwned else 1,
            "undetected": 0,
            "total_engines": 1,
            "decoded": masked,
        })


class ScanScreenshotView(View):
    @rate_limit(max_requests=6, window=60, key_prefix="scan_screenshot")
    def post(self, request):
        image = request.FILES.get("screenshot")

        if not image:
            return error_response("Скриншот не загружен")
        if not image.content_type or not image.content_type.startswith("image/"):
            return error_response("Нужен файл изображения")

        file_hash = get_file_sha256(image)

        cached = ScreenshotScan.objects.filter(file_hash=file_hash).first()
        if cached:
            return JsonResponse({**cached.result, "cached": True})

        suffix = os.path.splitext(image.name)[1] or ".png"
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
                for chunk in image.chunks():
                    tmp.write(chunk)
                tmp.flush()
                result = analyze_screenshot_with_gemini(tmp.name)
        except Exception as e:
            return self._handle_gemini_error(e)

        verdict = result.get("verdict", "suspicious")
        risk_score = result.get("risk_score", 50)

        response_data = {
            "status": "done",
            "scan_type": "screenshot",
            "verdict": verdict,
            "title": result.get("summary", "AI анализ скриншота"),
            "decoded": result.get("detected_brand", "unknown"),
            "recommendation": result.get("recommendation", ""),
            "risk_score": risk_score,
            "suspicious_indicators": result.get("suspicious_indicators", []),
            "is_official_likely": result.get("is_official_likely", False),
            "danger_percent": risk_score,
            "malicious": 1 if verdict == "dangerous" else 0,
            "suspicious": 1 if verdict == "suspicious" else 0,
            "harmless": 1 if verdict == "clean" else 0,
            "undetected": 0,
            "total_engines": 1,
            "cached": False,
        }

        ScreenshotScan.objects.create(file_hash=file_hash, result=response_data)
        return JsonResponse(response_data)

    def _handle_gemini_error(self, exc: Exception) -> JsonResponse:
        err = str(exc)
        logger.exception("Gemini analysis failed")
        if "429" in err:
            return error_response("AI лимит исчерпан. Попробуйте позже или завтра.", status=429)
        if "503" in err or "UNAVAILABLE" in err:
            return error_response("AI сервис временно перегружен. Попробуйте через пару минут.", status=503)
        return error_response("Ошибка AI анализа", status=500)
