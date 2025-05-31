from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),  # User registration route
    path('login/', views.login_view, name='login'),  # User login route
    path('upload_resume/', views.upload_resume, name='upload_resume'),
    path('show_skills/', views.show_skills, name='show_skills'), 
    path('start_interview/', views.start_interview, name='start_interview'),
    path('interview-summary/', views.interview_summary, name='interview_summary'),
    path('finish_interview/', views.finish_interview, name='finish_interview'),
    path('interview_results/', views.interview_results, name='interview_results'),
    path('download-pdf/', views.download_pdf, name='download_pdf'),
    path('interview-history/', views.interview_history, name='interview_history'),
    
    path('logout/', views.logout_view, name='logout'),
    path('', views.home, name='home'),
    
]

