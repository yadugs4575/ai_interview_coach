from django.contrib import admin
from .models import Resume

class ResumeAdmin(admin.ModelAdmin):
    list_display = ('user', 'resume_file', 'job_role', 'uploaded_at')  # Display the uploaded_at field
    list_filter = ('user', 'job_role')  # Allow filtering by user and job role
    search_fields = ('user__username', 'job_role')  # Enable searching by username or job role
    readonly_fields = ('resume_file', 'job_role', 'user', 'uploaded_at')  # Make certain fields readonly

    def resume_file_link(self, obj):
        if obj.resume_file:
            return f'<a href="{obj.resume_file.url}" target="_blank">Download</a>'
        return 'No file uploaded'

    resume_file_link.allow_tags = True  # This makes the link clickable in the admin interface

admin.site.register(Resume, ResumeAdmin)
