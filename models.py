from database import Base
import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Float, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from fastapi_utils.guid_type import GUID, GUID_DEFAULT_SQLITE
from sqlalchemy.types import TypeDecorator, String
import json

from uuid import UUID, uuid4  

class JSONEncodeDict(TypeDecorator):
	impl = String
	
	def process_bind_param(self, value, dialect):
		if value is not None:
			value = json.dumps(value)
		return value

	def process_result_value(self, value, dialect):
		if value is not None:
			value = json.loads(value)
		return value
		
class User(Base):
	__tablename__ = "user"
	
	id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	username = Column(String(30), unique=True, index=True) 
	email = Column(String(30), unique=True, nullable=False, index=True) 
	ci = Column(String(50), unique=True, nullable=False, index=True)
	nombre = Column(String(50), nullable=False, index=True) 
	primer_appellido = Column(String(50), nullable=True, index=True) 
	segundo_appellido = Column(String(50), nullable=True, index=True)  
	role = Column(JSONEncodeDict)
	disable = Column(Boolean, nullable=True, default=False)	
	hashed_password = Column(String(100), nullable=True, default=False)		
	
class Provincias(Base):
	__tablename__ = "provincias"
	
	id_provincia = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE) 
	nombre_provincia = Column(String(50), unique=True, nullable=False, index=True) 
	codigo_provincia = Column(String(15), unique=True, index=True) 
	#Relacion 1-M con tabla hija "Municipios"
	municipios_lista = relationship("Municipios", back_populates="provincia")
	
class Municipios(Base):
	__tablename__ = "municipios"
	
	id_municipio = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE) 
	nombre_municipio = Column(String(50), unique=True, nullable=False, index=True) 
	#Relacion M-1 con tabla padre "Provincias"
	provincia_id = Column(GUID, ForeignKey("provincias.id_provincia"))
	provincia = relationship("Provincias", back_populates="municipios_lista")	
	#Relacion 1-M con tabla hija "Estaciones"
	estaciones_lista = relationship("Estaciones", back_populates="municipio")
	
class Estaciones(Base):
	__tablename__ = "estaciones"
	
	id_estacion = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE) 
	nombre_estacion = Column(String(50), unique=True, nullable=False, index=True) 
	codigo_estacion = Column(String(15), unique=True, index=True) 
	altura_estacion = Column(Float, nullable=True, index=True)
	norte_estacion = Column(Float, nullable=True, index=True)
	sur_estacion = Column(Float, nullable=True, index=True)
	#Relacion M-1 con tabla padre "Municipios"
	municipio_id = Column(GUID, ForeignKey("municipios.id_municipio"))
	municipio = relationship("Municipios", back_populates="estaciones_lista")	
	#Relacion 1-M con tabla hija "Datos"
	datos_lista = relationship("Datos", back_populates="estacion")
	
class Datos(Base):
	__tablename__ = "datos"	
	
	id_dato = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE) 
	dato_fecha = Column(DateTime, onupdate=func.now())
	dato_valor = Column(Float, nullable=False, index=True)	
	#Relacion M-1 con tabla padre "Estaciones"
	estacion_id = Column(GUID, ForeignKey("estaciones.id_estacion"))
	estacion = relationship("Estaciones", back_populates="datos_lista")		
	#Agregar una restriccion de insertcion de datos (Estacion - Fecha)
	_table_args__ = (UniqueConstraint(estacion_id, dato_fecha), )
	
	
	
	


	
	
