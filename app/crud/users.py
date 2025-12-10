from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from .. import models, auth

async def create_user(db: AsyncSession, user: models.User):
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user

async def get_user_by_username(db: AsyncSession, username: str):
    result = await db.execute(select(models.User).where(models.User.username == username))
    return result.scalars().first()

# Админка 
async def get_all_users(db: AsyncSession, skip: int = 0, limit: int = 100):
    result = await db.execute(select(models.User).offset(skip).limit(limit))
    return result.scalars().all()

async def delete_user(db: AsyncSession, user_id: int):
    user = await get_user(db, user_id)
    if not user:
        return False
    
    await db.delete(user)
    await db.commit()
    return True

async def get_user(db: AsyncSession, user_id: int):
    result = await db.execute(select(models.User).where(models.User.id == user_id))
    return result.scalars().first()