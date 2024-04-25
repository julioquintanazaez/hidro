from typing import Union, Optional, List
from datetime import date
from pydantic import BaseModel, EmailStr 

class UserUPD(BaseModel):	
	email: Union[EmailStr, None] = None
	ci : Union[str, None] = None
	nombre : Union[str, None] = None	
	primer_appellido : Union[str, None] = None  
	segundo_appellido : Union[str, None] = None 
	role: List[str] = []
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class UserActivate(BaseModel):	
	disable: Union[bool, None] = None
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
	
class User(BaseModel):	
	username: str
	email: EmailStr
	ci : str
	nombre : str	
	primer_appellido : str  
	segundo_appellido : str 
	role: List[str] = []		
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	

class UserAdd(User):
	hashed_password: str
	
class UserInDB(UserAdd):
	id: str
	disable: Union[bool, None] = None
	
class UserPassword(BaseModel):
    hashed_password: str
	
class UserResetPassword(BaseModel):
	actualpassword: str
	newpassword: str

#-------------------------
#-------TOKEN-------------
#-------------------------
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
	username: Union[str, None] = None
	scopes: List[str] = []	

#-------------------------
#-----  PROVINCIA   ------
#-------------------------
class Provincias(BaseModel):	
	nombre_provincia : str
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class Provincias_InDB(Provincias):	
	id_provincia : str

#-------------------------
#-------  MUNICIPIO  -----
#-------------------------
class Municipios(BaseModel):	
	nombre_municipio : str
	provincia_id : str
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class Municipios_UPD(BaseModel):	
	nombre_municipio : str
	
class Municipios_InDB(Municipios):	
	id_municipio : str	
	
#-------------------------
#-----  ESTACIONES  ------
#-------------------------
class Estaciones(BaseModel):
	nombre_estacion : str 
	municipio_id : str
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class Estaciones_UPD(BaseModel):
	nombre_estacion : str 
	
class Estaciones_InDB(Estaciones):	
	id_estacion : str	

#-------------------------
#-------- DATOS ----------
#-------------------------
class Datos(BaseModel):
	dato_fecha : date  
	dato_valor : str
	estacion_id : str

	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class Datos_UPD(BaseModel):
	dato_valor : str  

class Datos_InDB(Datos):	
	id_dato : str	