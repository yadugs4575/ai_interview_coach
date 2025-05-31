
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import render, redirect
# users/views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Resume



import os
import spacy
from PyPDF2 import PdfReader
from docx import Document
from django.shortcuts import render, redirect
from .models import Resume



# Registration view
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import login
from django.contrib import messages
import re

# views.py
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
import re
from django.urls import reverse 

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import re





from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.db import IntegrityError
import re

def validate_username(username):
    """Validate username format (3-30 chars, letters, numbers, underscores)"""
    return bool(re.match(r'^[a-zA-Z0-9_]{3,30}$', username))

def validate_password(password):
    """Validate password strength"""
    return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$', password))

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        context = {'username': username, 'email': email}
        is_valid = True

        # Validate username
        if not username:
            messages.error(request, 'Username is required.')
            is_valid = False
        elif not validate_username(username):
            messages.error(request, 'Username must be 3-30 characters and can only contain letters, numbers, and underscores.')
            is_valid = False
        elif User.objects.filter(username__iexact=username).exists():
            messages.error(request, 'Username is already taken.')
            is_valid = False

        # Validate email
        if not email:
            messages.error(request, 'Email is required.')
            is_valid = False
        else:
            try:
                validate_email(email)
                if User.objects.filter(email__iexact=email).exists():
                    messages.error(request, 'This email is already registered.')
                    is_valid = False
            except ValidationError:
                messages.error(request, 'Please enter a valid email address.')
                is_valid = False

        # Validate password
        if not password:
            messages.error(request, 'Password is required.')
            is_valid = False
        elif not validate_password(password):
            messages.error(request, 'Password must be at least 8 characters with uppercase, lowercase, number, and special character.')
            is_valid = False

        # Check password confirmation
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            is_valid = False

        if is_valid:
            try:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password
                )
                login(request, user)
                return redirect(f"{reverse('login')}?welcome=true")
            
            except IntegrityError:
                messages.error(request, 'This username or email is already registered.')
            
            
        return render(request, 'myapp/register.html', context)

    return render(request, 'myapp/register.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('upload_resume')
        
    
    # Handle registered parameter for GET requests
    registered = request.GET.get('registered', False)
    return render(request, 'myapp/login.html', {'registered': registered})


import os
import re
import tempfile
import pdfplumber
from docx import Document
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from myapp.models import Resume
import google.generativeai as genai

# ✅ Configure Gemini API
genai.configure(api_key="AIzaSyBIcF_aqSeDl6Z3e1TPN9HXdO3w0Rr80H4")

# ✅ Settings
MAX_FILE_SIZE = getattr(settings, 'MAX_RESUME_SIZE', 10 * 1024 * 1024)  # 10MB
ALLOWED_EXTENSIONS = {'.pdf', '.docx', '.doc', '.txt', '.rtf', '.odt'}

@login_required
def upload_resume(request):
    if request.method == 'POST':
        resume_file = request.FILES.get('resume')
        job_role = request.POST.get('job_role', '')

        if not resume_file:
            messages.error(request, "⚠️ No file uploaded. Please select a resume file.")
            return redirect('upload_resume')

        # ✅ File validation
        if resume_file.size > MAX_FILE_SIZE:
            messages.error(request, f"❌ File too large (Max: {MAX_FILE_SIZE // 1024 // 1024}MB). Please upload a smaller file.")
            return redirect('upload_resume')

        file_ext = os.path.splitext(resume_file.name.lower())[1]
        if file_ext not in ALLOWED_EXTENSIONS:
            messages.error(request, "❌ Unsupported file format. Allowed formats: PDF, DOCX, DOC, TXT, RTF, ODT.")
            return redirect('upload_resume')

        try:
            # ✅ Save file temporarily
            fs = FileSystemStorage(location=tempfile.gettempdir())
            filename = fs.save(resume_file.name, resume_file)
            file_path = fs.path(filename)

            # ✅ Remove existing resume
            Resume.objects.filter(user=request.user).delete()

            # ✅ Create and process resume
            resume = Resume.objects.create(
                user=request.user,
                resume_file=resume_file,
                job_role=job_role,
                extracted_skills=[]
            )

            # ✅ Extract skills
            extracted_skills = extract_skills_from_resume(file_path)
            resume.extracted_skills = extracted_skills
            resume.save()

            # ✅ Prepare interview session
            request.session.update({
                'extracted_skills': extracted_skills,
                'job_role': job_role,
                'generated_questions': [],
                'question_index': 0,
                'interview_started': False,
            })

            return redirect('show_skills')

        except Exception as e:
            messages.error(request, f"❌ Error processing resume: {str(e)}")
            return redirect('upload_resume')

        finally:
            if 'file_path' in locals():
                fs.delete(filename)

    return render(request, 'myapp/upload_resume.html')

def extract_skills_from_resume(file_path):
    """Extracts skills from resumes using Gemini API"""
    try:
        text = extract_text_from_file(file_path)
        if not text:
            raise ValueError("No text extracted from resume")

        # ✅ AI-powered extraction
        model = genai.GenerativeModel("gemini-1.5-flash-latest")
        prompt = (
   "Extract all the skills listed under the **Skills** section in the following resume text. "
    "The skills are categorized into **Hard Skills**, **Techniques**, and **Tools**. "
    "Provide the extracted skills from all categories (Hard Skills, Techniques, and Tools) in a list format, "
    "and ensure there are no duplicates. Exclude any general software proficiency or soft skills. "
    "Each skill should be listed on a new line for clarity. \n\n"
    f"Resume:\n{text}"
)

        response = model.generate_content(prompt)

        # ✅ Process AI response
        extracted_skills = response.text.strip().split("\n")
        return sorted(set(extracted_skills), key=lambda x: x.lower())

    except Exception as e:
        raise RuntimeError(f"Skill extraction failed: {str(e)}")

def extract_text_from_file(file_path):
    """Extracts text from various resume file formats"""
    try:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.pdf':
            return extract_text_from_pdf(file_path)
        elif ext in {'.docx', '.doc', '.odt', '.rtf'}:
            return extract_text_from_word(file_path)
        elif ext == '.txt':
            return extract_text_from_txt(file_path)
        else:
            raise ValueError(f"Unsupported file type: {ext}")
    except Exception as e:
        raise RuntimeError(f"Text extraction error: {str(e)}")

def extract_text_from_pdf(pdf_path):
    """Extracts text from PDFs with optional OCR"""
    text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                text += page.extract_text() or ""
        return text.strip()
    except Exception as e:
        raise RuntimeError(f"PDF processing failed: {str(e)}")

def extract_text_from_word(file_path):
    """Handles Word document text extraction"""
    try:
        if file_path.lower().endswith('.docx'):
            doc = Document(file_path)
            return '\n'.join([p.text for p in doc.paragraphs]).strip()
        else:
            from subprocess import check_output
            return check_output(['antiword', file_path]).decode('utf-8', 'ignore')
    except Exception as e:
        raise RuntimeError(f"Word processing failed: {str(e)}")

def extract_text_from_txt(file_path):
    """Extracts text from plain text files with encoding detection"""
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
            for encoding in ['utf-8', 'iso-8859-1', 'windows-1252']:
                try:
                    return raw_data.decode(encoding)
                except UnicodeDecodeError:
                    continue
            return raw_data.decode('utf-8', 'ignore')
    except Exception as e:
        raise RuntimeError(f"Text file error: {str(e)}")


        
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from myapp.models import Resume

@login_required
def show_skills(request):
    """Allows users to dynamically add or remove extracted skills, but resets when a new resume is uploaded."""

    try:
        # Retrieve the latest uploaded resume for the logged-in user
        latest_resume = Resume.objects.filter(user=request.user).latest('uploaded_at')

        # Check if the stored resume ID in session is different from the latest resume
        if request.session.get('resume_id') != latest_resume.id:
            # Reset skills and job role when a new resume is uploaded
            request.session['extracted_skills'] = latest_resume.extracted_skills or []
            request.session['job_role'] = latest_resume.job_role or "Not Specified"
            request.session['resume_id'] = latest_resume.id  # Store current resume ID
            request.session.modified = True  # Mark session as modified

        skills = request.session.get('extracted_skills', [])
        job_role = request.session.get('job_role', "Not Specified")

        if request.method == "POST":
            action = request.POST.get("action", "").strip()
            skill_name = request.POST.get("skill", "").strip()

            if not action or not skill_name:
                return JsonResponse({"success": False, "error": "Missing required parameters."})

            if action == "add":
                if skill_name and skill_name not in skills:
                    skills.append(skill_name)
                    request.session['extracted_skills'] = skills
                    request.session.modified = True
                    return JsonResponse({"success": True, "message": f"Skill '{skill_name}' added successfully."})
                return JsonResponse({"success": False, "error": "Skill already exists!"})

            elif action == "remove":
                if skill_name in skills:
                    skills.remove(skill_name)
                    request.session['extracted_skills'] = skills
                    request.session.modified = True
                    return JsonResponse({"success": True, "message": f"Skill '{skill_name}' removed successfully."})
                return JsonResponse({"success": False, "error": "Skill not found!"})

            return JsonResponse({"success": False, "error": "Invalid request. Unknown action."})

        return render(request, 'myapp/show_skills.html', {
            'skills': skills,
            'job_role': job_role
        })

    except Resume.DoesNotExist:
        messages.warning(request, "No resumes found. Please upload your resume.")
        return redirect('upload_resume')













from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .generate_questions import generate_job_specific_questions
import re

def clean_question(question):
    """Cleans up generated interview questions by removing numbering, categories, and extra text."""

    # Remove numbering at the start (e.g., "1. ", "4. ")
    question = re.sub(r"^\d+\.\s*", "", question)

    # Remove category prefixes (like "Django", "Java", "Python", "SQL") if they appear at the start
    question = re.sub(r"^(Django|Java|Python|SQL|Machine Learning|Data Science|React):?\s*", "", question, flags=re.IGNORECASE)

    # Remove common headings that might appear
    unwanted_phrases = [
        "Beginner-Friendly Data Scientist Interview Questions",
        "Advanced Data Science Interview Questions",
        "Python Interview Questions",
        "Java Interview Questions",
        "Django Interview Questions",
        "SQL Interview Questions"
    ]
    
    for phrase in unwanted_phrases:
        if phrase.lower() in question.lower():
            return ""  # Remove entire heading

    return question.strip()









from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from myapp.models import InterviewResponse  # Import the new model
import logging

logger = logging.getLogger(__name__)

@login_required
def start_interview(request):
    """Handles interview question display with navigation (Previous, Skip, Next, Finish)."""
    
    skills = request.session.get('extracted_skills', [])
    job_role = request.session.get('job_role', None)

    if not skills or not job_role:
        messages.error(request, "Please extract skills and job role first.")
        return redirect('show_skills')

    # Create user-specific session key with resume signature
    resume_signature = f"{job_role}_{hash(tuple(sorted(skills)))}"
    user_key = f"user_{request.user.id}_interview_{resume_signature}"
    
    # Initialize fresh session data if needed
    if (user_key not in request.session or 
        request.session[user_key].get('resume_signature') != resume_signature):
        request.session[user_key] = {
            'generated_questions': [],
            'question_index': 0,
            'answers': {},
            'resume_signature': resume_signature
        }

    interview_data = request.session[user_key]
    questions = interview_data['generated_questions']
    question_index = interview_data['question_index']
    session_answers = interview_data['answers']
    total_questions = len(questions)
    current_question = questions[question_index] if questions else None

    if request.method == "POST":
        if "restart" in request.POST:
            # Clear all answers from database
            with transaction.atomic():
                InterviewResponse.objects.filter(
                    user=request.user,
                    job_role=job_role
                ).delete()
            
            # Clear session data and force empty answer
            interview_data.update({
                'question_index': 0,
                'answers': {}
            })
            request.session[user_key] = interview_data
            
            # Return a fresh response with empty answer
            return render(request, 'myapp/start_interview.html', {
                'job_role': job_role,
                'skills': skills,
                'current_question': questions[0] if questions else None,
                'question_index': 0,
                'total_questions': len(questions),
                'questions_exist': bool(questions),
                'answer': ''  # Force empty answer
            })
            
    if request.method == "POST":
        logger.info(f"Before Update - Question Index: {question_index}")

        if "generate" in request.POST:
            generated_questions = generate_job_specific_questions(skills, job_role)

            if generated_questions:
                cleaned_questions = [clean_question(q) for q in generated_questions if clean_question(q)]
                interview_data.update({
                    'generated_questions': cleaned_questions,
                    'question_index': 0,
                    'answers': {},
                    'interview_started': True
                })
                request.session[user_key] = interview_data
                return redirect('start_interview')

        # Handle answer submission for all actions except generate
        user_answer = request.POST.get('answer', '').strip()
        if current_question and user_answer:
            session_answers[str(question_index)] = user_answer
            interview_data['answers'] = session_answers
            with transaction.atomic():
                InterviewResponse.objects.update_or_create(
                    user=request.user,
                    job_role=job_role,
                    question=current_question,
                    defaults={'answer': user_answer}
                )

        if "previous" in request.POST and question_index > 0:
            interview_data['question_index'] -= 1
        elif "skip" in request.POST and question_index < total_questions - 1:
            interview_data['question_index'] += 1
        elif "next" in request.POST and question_index < total_questions - 1:
            interview_data['question_index'] += 1
        elif "restart" in request.POST:
            # Bulk delete all answers for this user/job_role combination
            with transaction.atomic():
                InterviewResponse.objects.filter(
                    user=request.user,
                    job_role=job_role
                ).delete()
            
            interview_data.update({
                'question_index': 0,
                'answers': {}
            })
            messages.info(request, "Interview restarted. All answers cleared.")
        elif "finish" in request.POST:
            messages.success(request, "Interview completed! Well done.")
            return redirect('finish_interview')

        # Save session changes
        request.session[user_key] = interview_data
        return redirect('start_interview')

    # Get current answer if exists
    current_answer = session_answers.get(str(question_index), '')

    return render(request, 'myapp/start_interview.html', {
        'job_role': job_role,
        'skills': skills,
        'current_question': current_question,
        'question_index': question_index,
        'total_questions': total_questions,
        'questions_exist': bool(questions),
        'answer': current_answer
    })




import json
import google.generativeai as genai
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.contrib import messages
from .models import InterviewResponse
import re









# ✅ Configure Gemini
GEMINI_API_KEY = "AIzaSyCFVlKM8GrfHiIyEHKG-Wr6h0f6KJLeOwo"
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel(model_name="models/gemini-1.5-flash")


# ✅ Helper: Evaluate answers in batch using Gemini
def evaluate_batch_with_gemini(responses):
    qa_list = [{"question": r.question, "answer": r.answer} for r in responses]

    prompt = f"""
You are an expert interview evaluator.

Evaluate the candidate's responses below. For each item, give:
- A score out of 10.
- Two-line constructive feedback.

Return ONLY a JSON array in the following format:
[
  {{
    "question": "Question text",
    "score": int,
    "feedback": "string"
  }},
  ...
]

Candidate's Responses:
{json.dumps(qa_list, indent=2)}
    """

    try:
        response = model.generate_content(prompt)
        raw = response.candidates[0].content.parts[0].text.strip()
        cleaned = re.sub(r"^```json|^```|```$", "", raw).strip()
        return json.loads(cleaned)
    except Exception as e:
        print(f"[Gemini Evaluation Error] {e}")
        return []


# ✅ Finish Interview: Save answers, generate expected answers, get scores
@login_required
def finish_interview(request):
    job_role = request.session.get('job_role')
    skills = request.session.get('extracted_skills', [])
    resume_signature = f"{job_role}_{hash(tuple(sorted(skills)))}"
    user_key = f"user_{request.user.id}_interview_{resume_signature}"

    interview_data = request.session.get(user_key)
    if not interview_data:
        messages.error(request, "No interview data found.")
        return redirect('start_interview')

    questions = interview_data.get('generated_questions', [])
    answers = interview_data.get('answers', {})

    # Store each answer with expected answer
    for idx, question in enumerate(questions):
        answer = answers.get(str(idx), "").strip()

        try:
            response = model.generate_content(
                f"""As an expert interviewer, give a brief and ideal answer (1–2 lines max) for the following interview question, suitable for the role of {job_role}.
                Keep the answer concise, practical, and easy to understand and for beginner.

                Question: {question}"""
            )
            expected = response.text.strip() if hasattr(response, 'text') else "Expected answer not available."
        except Exception as e:
            print(f"[Expected Answer Error] {e}")
            expected = "Expected answer not available."

        InterviewResponse.objects.update_or_create(
            user=request.user,
            job_role=job_role,
            question=question,
            defaults={
                'answer': answer,
                'score': 0.0,
                'feedback': "Not attended" if not answer else "",
                'expected_answer': expected
            }
        )

    all_responses = InterviewResponse.objects.filter(user=request.user, job_role=job_role)
    evaluated_results = evaluate_batch_with_gemini(all_responses)

    # Save scores and feedback
    for r in all_responses:
        result = next((res for res in evaluated_results if res["question"] == r.question), None)
        if result:
            r.score = result.get("score", 0.0)
            r.feedback = result.get("feedback", "No feedback")
            r.save()

    messages.success(request, "Interview completed and evaluated.")
    return redirect('interview_results')


def get_score_class(score):
    if score >= 8:
        return 'high-score'      # Excellent performance
    elif score >= 5:
        return 'mid-score'       # Good/average performance
    else:
        return 'low-score'       # Needs improvement



# ✅ Interview Results View
@login_required
def interview_results(request):
    job_role = request.session.get('job_role')
    if not job_role:
        messages.error(request, "Job role not found in session.")
        return redirect('start_interview')

    responses = InterviewResponse.objects.filter(user=request.user, job_role=job_role)
    results = []
    total_score = 0
    answered_count = 0

    for r in responses:
        skipped = not r.answer or r.answer.strip() == ""
        score = round(r.score, 1) if not skipped else None
        feedback = r.feedback if not skipped else "You skipped this question."

        if not skipped:
            answered_count += 1
            total_score += r.score

        results.append({
            'question': r.question,
            'answer': r.answer if r.answer else "Not attended",
            'expected_answer': r.expected_answer or "Expected answer not available.",
            'score': score,
            'feedback': feedback,
            'skipped': skipped,
            'score_class': get_score_class(r.score if not skipped else 0)
        })

    total_questions = len(results)
    skipped_count = total_questions - answered_count
    average_score = round(total_score / answered_count, 1) if answered_count else 0

    # Optional verdict logic
    if average_score >= 8:
        verdict = "Excellent performance"
    elif average_score >= 5:
        verdict = "Good effort, but can improve"
    else:
        verdict = "Needs improvement"

    return render(request, 'myapp/interview_results.html', {
        'job_role': job_role,
        'results': results,
        'summary': {
            'total_questions': total_questions,
            'answered': answered_count,
            'skipped': skipped_count,
            'total_score': round(total_score, 1),
            'average_score': average_score,
            'verdict': verdict
        }
    })


# ✅ Download results as PDF
import pdfkit
from django.http import HttpResponse
from django.template.loader import get_template

@login_required
def download_pdf(request):
    template = get_template('myapp/interview_results.html')

    user = request.user
    job_role = request.session.get('job_role')

    if not job_role:
        return HttpResponse("Job role not found in session.", status=400)

    responses = InterviewResponse.objects.filter(user=user, job_role=job_role)
    html = template.render({'results': responses, 'job_role': job_role}, request=request)

    try:
        path_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'  # Update if needed
        config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)

        pdf_file = pdfkit.from_string(html, False, configuration=config)

        response = HttpResponse(pdf_file, content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="interview_results.pdf"'
        return response
    except Exception as e:
        return HttpResponse(f"PDF generation failed: {str(e)}", status=500)








def interview_summary(request):
    return render(request, 'myapp/interview_summary.html')


def logout_view(request):
    logout(request)
    return redirect('login') 



from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count
from .models import InterviewResponse
from django.utils.timezone import localtime

@login_required
def interview_history(request):
    user = request.user
    responses = InterviewResponse.objects.filter(user=user).order_by('created_at')

    # Group data for charts
    scores_over_time = [
        {
            "date": localtime(r.created_at).strftime('%Y-%m-%d %H:%M'),
            "score": r.score
        }
        for r in responses if r.answer
    ]

    by_job_role = (
        InterviewResponse.objects
        .filter(user=user)
        .values('job_role')
        .annotate(
            avg_score=Avg('score'),
            total=Count('id'),
            answered=Count('answer'),
            skipped=Count('id') - Count('answer')
        )
    )

    return render(request, 'interview_history.html', {
        'responses': responses,
        'scores_over_time': scores_over_time,
        'by_job_role': list(by_job_role),
    })



from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import InterviewResponse


















def home(request):
    return render(request, 'myapp/home.html')  # Ensure this line is indented properly



