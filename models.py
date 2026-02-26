from pydantic import BaseModel, Field, field_validator

# Для Задания 1.4
class User(BaseModel):
    name: str
    id: int

# Для Задания 1.5*
class UserAge(BaseModel):
    name: str
    age: int

# Для Задания 2.2* (включает требования 2.1)
class Feedback(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    message: str = Field(min_length=10, max_length=500)

    @field_validator('message')
    @classmethod
    def check_forbidden_words(cls, v: str) -> str:
        # Проверка на недопустимые слова в любых падежах и регистрах
        forbidden = ["кринж", "рофл", "вайб"]
        v_lower = v.lower()
        for word in forbidden:
            if word in v_lower:
                raise ValueError("Использование недопустимых слов")
        return v