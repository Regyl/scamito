import random

LAST_PHONE_LENGTH = 7
MIDDLE_CODES = ["495", "967", "926", "790", "123", "903", "900", "800", "945", "496", "497", "623", "523", "807", "903", "125"]

def get() -> str:
    phone = "7"
    middle = random.choice(MIDDLE_CODES)
    phone += str(middle)
    for i in range(LAST_PHONE_LENGTH):
        num = random.randint(0, 9)
        phone += str(num)
    return phone