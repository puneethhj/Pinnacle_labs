import re
from zxcvbn import zxcvbn

# Function to evaluate password strength
def evaluate_password(password):
    # Initialize the strength score
    score = 0
    feedback = []

    # Check length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    # Check for uppercase letters
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Password should contain at least one uppercase letter.")

    # Check for lowercase letters
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Password should contain at least one lowercase letter.")

    # Check for digits
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Password should contain at least one digit.")

    # Check for special characters
    if re.search(r'[\W_]', password):
        score += 1
    else:
        feedback.append("Password should contain at least one special character.")

    # Check for common passwords using zxcvbn
    zxcvbn_result = zxcvbn(password)
    zxcvbn_score = zxcvbn_result['score']

    if zxcvbn_score < 3:
        feedback.append("Password is too common or weak.")
    else:
        score += 1

    # Overall score
    overall_score = (score + zxcvbn_score) / 2

    # Recommend secure password practices
    recommendations = []
    if overall_score < 4:
        recommendations.append("Consider using a longer password with a mix of uppercase, lowercase, digits, and special characters.")
        recommendations.append("Avoid common patterns and words.")
        recommendations.append("Use a password manager to generate and store strong passwords.")

    return {
        "password": password,
        "score": overall_score,
        "feedback": feedback,
        "recommendations": recommendations
    }

# Example usage
password = "P@ssw0rd"
result = evaluate_password(password)

print(f"Password: {result['password']}")
print(f"Strength Score: {result['score']}/5")
print("Feedback:")
for fb in result['feedback']:
    print(f" - {fb}")
print("Recommendations:")
for rec in result['recommendations']:
    print(f" - {rec}")
