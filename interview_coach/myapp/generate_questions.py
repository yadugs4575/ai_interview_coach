import requests
import json
import re


GEMINI_API_KEY = "AIzaSyBLoNtCJrn48Q5sRW3Te8hJRifBE-QFDVE"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
def generate_job_specific_questions(skills, job_role):
    if not skills or not job_role:
        return ["Error: Missing job role or skills. Please update your resume and try again."]

    skill_list = ", ".join(skills)
    prompt_text = (
    f"I am a beginner preparing for an interview for the role of {job_role}. "
    f"My skills include {skill_list}. "
    "Generate exactly 15 interview questions in a numbered list (1-15). "
    "The first 12 questions should be technical, strictly related to the skills mentioned. "
    "The remaining 3 questions should focus on the job role, covering responsibilities, and industry scenarios. "
    "Ensure all questions are simple and beginner-friendly. "
    "Return only the numbered list from 1 to 15 without any explanations, introductions, or extra text."
)


    payload = {"contents": [{"parts": [{"text": prompt_text}]}]}

    try:
        response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        response_data = response.json()
        print(response_data)  # ✅ Debugging: Print full response

        if "candidates" in response_data:
            generated_text = response_data["candidates"][0]["content"]["parts"][0]["text"]
            return clean_questions(generated_text)

        return ["Error: No valid response from Gemini API."]
    
    except requests.exceptions.RequestException as e:
        return [f"Error: API request failed. {str(e)}"]

def clean_questions(text):
    cleaned_questions = [re.sub(r'^\d*\.*\s*', '', line).strip() for line in text.split("\n") if line]
    return cleaned_questions[:15] 

if __name__ == "__main__":
    test_skills = ["Python", "Django", "SQL", "REST APIs"]
    test_job_role = "Backend Developer"

    generated_questions = generate_job_specific_questions(test_skills, test_job_role)
    for i, q in enumerate(generated_questions, 1):
        print(f"{i}. {q}")
