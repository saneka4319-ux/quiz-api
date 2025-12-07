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