import random
import string
import base64
username = "tiagocmendes@ua.pt"

lines = ["1", "2", "3", "4", "5", "6", "7", "8"]
columns = ["a", "b", "c", "d", "e", "f", "g", "h"]

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    letters += "123456789_~^!/"
    return ''.join(random.choice(letters) for i in range(stringLength))

with open(username.split("@")[0] + ".csv", "w") as f:
    f.write("\ta\tb\tc\td\te\tf\tg\th\n")
    for l in lines:
        f.write(l + "\t")
        for c in columns:
            f.write(str(random.randint(100,999)) + "\t")
        f.write("\n")
    
    f.write("\nPASSWORD:\t" + randomString())
    f.write("\nPERMISSIONS:\ta-t")
    


