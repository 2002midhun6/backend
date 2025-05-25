from django.contrib import admin
from .models import ProfessionalProfile 
@admin.register(ProfessionalProfile)
class ProfessionalProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'bio', 'experience_years', 'availability_status')  # Customize display
    search_fields = ('user__username', 'bio')  # Enable searching
    list_filter = ('availability_status', 'experience_years')
# Register your models here.
