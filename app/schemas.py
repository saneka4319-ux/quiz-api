from pydantic import BaseModel, field_validator
from typing import Optional

class UserResponse(BaseModel):
    username: str

    class Config:
        from_attributes = True

class QuizCreate(BaseModel):
    title: str
    description: Optional[str] = None

class QuizUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None

class QuizOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    owner_id: int

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    username: str
    password: str

    @field_validator('password')
    @classmethod
    def validate_password_length(cls, v: str) -> str:
        if len(v.encode('utf-8')) > 72:
            raise ValueError('Пароль не может быть длиннее 72 байт')
        return v

class Token(BaseModel):
    access_token: str
    token_type: str


    
class OptionCreate(BaseModel):
    text: str
    is_correct: bool = False

class QuestionCreate(BaseModel):
    text: str
    options: list[OptionCreate]

class QuizCreateWithQuestions(BaseModel):
    title: str
    description: Optional[str] = None
    questions: list[QuestionCreate]



class OptionOut(BaseModel):
    id: int
    text: str
    is_correct: bool

    class Config:
        from_attributes = True

class QuestionOut(BaseModel):
    id: int
    text: str
    options: list[OptionOut]

    class Config:
        from_attributes = True

class QuizOutFull(BaseModel):
    id: int
    title: str
    description: Optional[str]
    owner_id: int
    questions: list[QuestionOut]

    class Config:
        from_attributes = True