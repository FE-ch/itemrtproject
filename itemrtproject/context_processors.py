from django.conf import settings

# Use for returning specific site values from settings.py
def site_values(request):
    # Add new values here
    values = {
        'PROJECT_NAME': settings.PROJECT_NAME,
    }

    return values