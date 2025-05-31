from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone



class Resume(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    resume_file = models.FileField(upload_to='resumes/')
    job_role = models.CharField(max_length=255)
    extracted_text = models.TextField(blank=True, null=True)  # Store extracted resume text
    extracted_skills = models.JSONField(blank=True, null=True)  # Store extracted skills
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.job_role} - {self.uploaded_at}"


from django.contrib.auth.models import User
from django.db import models

from django.contrib.auth.models import User
from django.db import models

class InterviewResponse(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    job_role = models.CharField(max_length=255)
    question = models.TextField()
    answer = models.TextField(blank=True, null=True)
    score = models.FloatField(default=0.0)
    feedback = models.TextField(blank=True, null=True)
    expected_answer = models.TextField(blank=True, null=True)  # ➕ New field
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.job_role} - {self.question[:50]}"


