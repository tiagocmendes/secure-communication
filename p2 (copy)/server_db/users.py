import random
import string
import base64

first_names = ["André", "Bernardo", "Carlos",
               "Diogo", "João", "Pedro", "Tiago", "Vasco"]
last_names = ["Amorim", "Barroso", "Carvalho",
              "Pereira", "Mendes", "Vasconcelos", "Silva"]



def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    letters += "123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
    return ''.join(random.choice(letters) for i in range(stringLength))


permissions = ['A1-T0', 'A1-T1']

def main():
    with open('users.csv', 'w') as f:
        f.write("Username\tPassword\tPermissions\n")
        for i in range(10):
            fname = random.choice(first_names)
            lname = random.choice(last_names)
            username = fname.lower() + "_" + lname.lower() + str(i) + "@ua.pt"
            plain_password = randomString(20)
            f.write(f"{username}\t{plain_password}\t{random.choice(permissions)}\n")


if __name__ == '__main__':
    main()