from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Enum, Boolean, Float
from sqlalchemy.orm import relationship, declarative_base
import enum
import datetime

Base = declarative_base()

class SeverityEnum(enum.Enum):
    critical = 'Critical'
    high = 'High'
    medium = 'Medium'
    low = 'Low'
    info = 'Info'

class Project(Base):
    __tablename__ = 'projects'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    vulnerabilities = relationship('Vulnerability', back_populates='project')
    scan_histories = relationship('ScanHistory', back_populates='project')

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'))
    name = Column(String)
    severity = Column(Enum(SeverityEnum))
    ip_address = Column(String)
    description = Column(Text)
    impact = Column(Text)
    recommendation = Column(Text)
    plugin_id = Column(String)
    cvss_score = Column(Float)
    owasp_category = Column(String)
    url = Column(String)
    poc = Column(Text)
    status = Column(String, default='Open')  # Open, In Progress, Mitigated, Accepted
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    project = relationship('Project', back_populates='vulnerabilities')
    comments = relationship('Comment', back_populates='vulnerability')

class ScanHistory(Base):
    __tablename__ = 'scan_histories'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'))
    scan_date = Column(DateTime, default=datetime.datetime.utcnow)
    file_path = Column(String)
    summary = Column(Text)
    project = relationship('Project', back_populates='scan_histories')

class Comment(Base):
    __tablename__ = 'comments'
    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    vulnerability = relationship('Vulnerability', back_populates='comments')
    user = relationship('User', back_populates='comments')

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True)
    is_admin = Column(Boolean, default=False)
    comments = relationship('Comment', back_populates='user')
    badges = relationship('Badge', back_populates='user')

class Badge(Base):
    __tablename__ = 'badges'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    name = Column(String)
    description = Column(Text)
    awarded_at = Column(DateTime, default=datetime.datetime.utcnow)
    user = relationship('User', back_populates='badges') 