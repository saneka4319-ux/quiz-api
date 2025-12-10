from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete, update
from sqlalchemy.orm import selectinload
from .. import models, schemas

async def get_quiz(db: AsyncSession, quiz_id: int):
    result = await db.execute(
        select(models.Quiz)
        .where(models.Quiz.id == quiz_id)
        .options(
            selectinload(models.Quiz.owner),
            selectinload(models.Quiz.questions).selectinload(models.Question.options)
        )
    )
    return result.scalars().first()

async def get_quizzes(db: AsyncSession, skip: int = 0, limit: int = 100):
    """Получить все тесты (публичные) со всей информацией об авторах"""
    result = await db.execute(
        select(models.Quiz)
        .options(selectinload(models.Quiz.owner))  # Загружаем информацию об авторах
        .offset(skip)
        .limit(limit)
        .order_by(models.Quiz.created_at.desc())  # Сначала новые тесты
    )
    return result.scalars().all()

async def get_user_quizzes(db: AsyncSession, user_id: int, skip: int = 0, limit: int = 100):
    """Получить тесты только определенного пользователя"""
    result = await db.execute(
        select(models.Quiz)
        .where(models.Quiz.owner_id == user_id)
        .options(selectinload(models.Quiz.owner))
        .offset(skip)
        .limit(limit)
        .order_by(models.Quiz.created_at.desc())
    )
    return result.scalars().all()

async def create_quiz(db: AsyncSession, quiz: schemas.QuizCreate, owner_id: int):
    db_quiz = models.Quiz(title=quiz.title, description=quiz.description, owner_id=owner_id)
    db.add(db_quiz)
    await db.commit()
    await db.refresh(db_quiz)
    return db_quiz

async def update_quiz(db: AsyncSession, quiz_id: int, quiz_update: schemas.QuizUpdate):
    stmt = (
        update(models.Quiz)
        .where(models.Quiz.id == quiz_id)
        .values(**quiz_update.model_dump(exclude_unset=True))
        .execution_options(synchronize_session="fetch")
    )
    await db.execute(stmt)
    await db.commit()
    return await get_quiz(db, quiz_id)

async def delete_quiz(db: AsyncSession, quiz_id: int):
    quiz = await get_quiz(db, quiz_id)
    if not quiz:
        return False
    
    await db.delete(quiz)
    await db.commit()
    return True

async def delete_question(db: AsyncSession, question_id: int):
    result = await db.execute(select(models.Question).where(models.Question.id == question_id))
    question = result.scalars().first()
    if not question:
        return False
    
    await db.delete(question)
    await db.commit()
    return True

async def create_quiz_with_questions(db: AsyncSession, quiz_data: schemas.QuizCreateWithQuestions, owner_id: int):
    db_quiz = models.Quiz(title=quiz_data.title, description=quiz_data.description, owner_id=owner_id)
    db.add(db_quiz)
    await db.flush()  # Получаем id теста

    for q in quiz_data.questions:
        db_question = models.Question(text=q.text, quiz_id=db_quiz.id)
        db.add(db_question)
        await db.flush()
        for opt in q.options:
            db_option = models.Option(text=opt.text, is_correct=opt.is_correct, question_id=db_question.id)
            db.add(db_option)

    await db.commit()
    await db.refresh(db_quiz)
    return db_quiz

async def get_all_quizzes_with_users(db: AsyncSession, skip: int = 0, limit: int = 100):
    result = await db.execute(
        select(models.Quiz)
        .options(selectinload(models.Quiz.owner))  
        .offset(skip)
        .limit(limit)
        .order_by(models.Quiz.created_at.desc())
    )
    return result.scalars().all()

async def get_quizzes_with_owners(db: AsyncSession, skip: int = 0, limit: int = 100):
    """Получить все тесты с загруженными владельцами для публичного отображения"""
    result = await db.execute(
        select(models.Quiz)
        .options(selectinload(models.Quiz.owner))  # Загружаем владельцев тестов
        .offset(skip)
        .limit(limit)
        .order_by(models.Quiz.created_at.desc())  # Сначала новые тесты
    )
    return result.scalars().all()