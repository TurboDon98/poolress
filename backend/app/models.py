from sqlalchemy import Column, Integer, String, DateTime, BigInteger, Float, Boolean, ForeignKey, Index
from datetime import datetime
from .db import Base

class ProjectFile(Base):
  __tablename__ = 'project_files'
  id = Column(Integer, primary_key=True, index=True)
  original_name = Column(String, nullable=False)
  stored_name = Column(String, nullable=False)
  stored_path = Column(String, nullable=False)
  content_type = Column(String, nullable=True)
  size_bytes = Column(BigInteger, nullable=True)
  uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class ProjectMeta(Base):
  __tablename__ = 'project_meta'
  id = Column(Integer, primary_key=True, index=True)
  file_id = Column(Integer, index=True, nullable=False)
  name = Column(String, nullable=True)
  author = Column(String, nullable=True)
  resources = Column(String, nullable=True)
  start_date = Column(DateTime, nullable=True)
  finish_date = Column(DateTime, nullable=True)
  actual_finish_date = Column(DateTime, nullable=True)
  percent_complete = Column(Float, nullable=True)
  created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class ResourcePerson(Base):
  __tablename__ = 'resource_people'
  id = Column(Integer, primary_key=True, index=True)
  name = Column(String, nullable=False)
  group = Column(String, nullable=True)
  department = Column(String, nullable=True)
  position = Column(String, nullable=True)
  rate = Column(String, nullable=True)
  created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class ResourceState(Base):
  __tablename__ = 'resource_state'
  id = Column(Integer, primary_key=True, index=True)
  current_file_name = Column(String, nullable=True)
  updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class WorkCalendar(Base):
  __tablename__ = 'work_calendar'
  id = Column(Integer, primary_key=True, index=True)
  name = Column(String, nullable=True)
  data_json = Column(String, nullable=True)
  updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class User(Base):
  __tablename__ = 'users'
  id = Column(Integer, primary_key=True, index=True)
  email = Column(String, unique=True, index=True, nullable=False)
  username = Column(String, unique=True, index=True, nullable=True)
  full_name = Column(String, nullable=True)
  # New fields requested for frontend compatibility
  department = Column(String, nullable=True)
  position = Column(String, nullable=True)
  
  role = Column(String, nullable=True)
  password_salt = Column(String, nullable=False)
  password_hash = Column(String, nullable=False)
  is_active = Column(Boolean, default=True, nullable=False)
  created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
  updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class UserSession(Base):
  __tablename__ = 'user_sessions'
  id = Column(Integer, primary_key=True, index=True)
  user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
  token = Column(String, unique=True, index=True, nullable=False)
  user_agent = Column(String, nullable=True)
  created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
  last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
  expires_at = Column(DateTime, nullable=True)

Index('idx_user_email', User.email)
Index('idx_user_username', User.username)
Index('idx_session_token', UserSession.token)
