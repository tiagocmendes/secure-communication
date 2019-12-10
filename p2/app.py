import sys

def login_password():
    print("\n1 - Sign In with password")

def main():
    print("---------------")
    print("SIO - Project 3")
    print("---------------")
    print("1 - Sign In with password")
    print("2 - Sign In with citizen card")
    print("3 - Exit")
    op = input("\nOption: ")

    if op == "1":
        login_password()
    else:
        print("Exiting...")
        sys.exit(0)

if __name__ == '__main__':
    while True:
        main()