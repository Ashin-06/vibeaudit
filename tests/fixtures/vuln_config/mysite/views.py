from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt  # expect: AUTH009
def update_profile(request):
    return JsonResponse({"ok": True})
