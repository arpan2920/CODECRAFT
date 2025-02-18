import re

def assess_password_strength(password):

    strength = 0
    feedback = []


    if len(password) < 8:
        feedback.append("Password is too short. It should be at least 8 characters long.")
    else:
        strength += 1


    if re.search(r"[A-Z]", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one uppercase letter.")


    if re.search(r"[a-z]", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one lowercase letter.")


    if re.search(r"[0-9]", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one number.")


    if re.search(r"[^A-Za-z0-9]", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one special character.")


    if strength == 5:
        password_strength = "Strong"
    elif strength >= 3:
        password_strength = "Medium"
    else:
        password_strength = "Weak"

    return {
        "password_strength": password_strength,
        "feedback": feedback
    }

def main():
    password = input("Enter a password: ")
    result = assess_password_strength(password)

    print(f"Password Strength: {result['password_strength']}")
    if result['feedback']:
        print("Feedback:")
        for item in result['feedback']:
            print(item)

if __name__ == "__main__":
    main()