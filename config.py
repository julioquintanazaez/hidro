from dotenv import load_dotenv
from os import getenv

#Load envirnment variables
load_dotenv()

ALGORITHM = getenv("ALGORITHM")
SECRET_KEY = getenv("SECRET_KEY")
APP_NAME = getenv("APP_NAME")
ACCESS_TOKEN_EXPIRE_MINUTES = getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
ADMIN_USER = getenv("ADMIN_USER")
ADMIN_NOMBRE = getenv("ADMIN_NOMBRE")
ADMIN_PAPELLIDO = getenv("ADMIN_PAPELLIDO")
ADMIN_SAPELLIDO = getenv("ADMIN_SAPELLIDO")
ADMIN_CI = getenv("ADMIN_CI")
ADMIN_CORREO = getenv("ADMIN_CORREO")
ADMIN_PASS = getenv("ADMIN_PASS")