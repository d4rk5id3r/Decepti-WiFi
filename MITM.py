import uos 


class Creds:
    Pass_Logs     = "./logs.txt"

    def __init__(self, email=None, password=None):
        self.email     = email
        self.password  = password

    def write(self):
        """Write credentials to CRED_FILE if valid input found."""
        if self.is_valid():
            with open(self.Pass_Logs, "wb") as f:
                f.write(b",".join([self.email, self.password]))
            print("Wrote credentials to {:s}".format(self.Pass_Logs))



    def load(self):

        try:
            with open(self.Pass_Logs, "rb") as f:
                contents = f.read().split(b",")
                print("Loaded Credentials from {:s}".format(self.Pass_Logs))
                if len(contents) == 2:
                    self.email, self.password = contents

                if not self.is_valid():
                    self.remove()

        except OSError:
            pass

        return self


    def remove(self):
        """
        1. Delete credentials file from disk.
        2. Set email and password to None
        """         

        # print("Attempting to remove {}".format(self.CRED_FILE))
        try:
            uos.remove(self.Pass_Logs)
        except OSError:
            pass

        self.email = self.password = None 



    def is_valid(self):
        # Ensure the credentials are entered as bytes
        if not isinstance(self.email, bytes):
            return False
        if not isinstance(self.password, bytes):
            return False

        # Ensure credentials are not None or empty
        return all((self.email, self.password))                          
