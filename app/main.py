from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select
from typing import Optional, Annotated
from datetime import timedelta
from . import schemas, crud, database, models, auth
from jose import JWTError

app = FastAPI(
    title="📚 Quiz API — Сервис создания тестов",
    description="""
    Сервис для создания, редактирования и прохождения тестов и опросов.

    🔒 Все операции с тестами требуют **авторизации**.
    📝 Сначала зарегистрируйтесь, затем войдите и начинайте создавать!
    """,
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "🔐 Аутентификация",
            "description": "Регистрация и вход в систему. Получение JWT-токена."
        },
        {
            "name": "📝 Тесты (Quizzes)",
            "description": "CRUD-операции с тестами. Доступны **только авторизованным пользователям**."
        },
        {
            "name": "🌍 Публичные эндпоинты",
            "description": "Просмотр списка тестов без авторизации."
        }
    ]
)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin" 

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

@app.on_event("startup")
async def init_models():
    async with database.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)

# === Вспомогательная функция для веб-слоя ===
async def get_user_from_token(token: str, db: AsyncSession):
    try:
        payload = auth.jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return await auth.get_user(db, username)
    except JWTError:
        return None

# === HTML Routes ===

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root_redirect(request: Request, db: AsyncSession = Depends(database.get_db)):
    token = request.cookies.get("token") or ""
    current_user = await get_user_from_token(token, db)
    if current_user:
        return RedirectResponse(url="/quizzes", status_code=status.HTTP_303_SEE_OTHER)
    else:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

@app.get("/register", response_class=HTMLResponse, include_in_schema=False)
async def register_page(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse("register.html", {"request": request, "error": error})

@app.get("/logout", include_in_schema=False)
async def logout(response: Response):
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="token",
        value="",
        httponly=False,
        max_age=0,
        expires=0,
        path="/"
    )
    return response

@app.get("/quizzes", response_class=HTMLResponse, include_in_schema=False)
async def quizzes_page(request: Request, db: AsyncSession = Depends(database.get_db)):
    token = request.cookies.get("token") or ""
    current_user = await get_user_from_token(token, db)
    if not current_user:
        return RedirectResponse(url="/login?error=Требуется%20авторизация", status_code=303)
    
    quizzes = await crud.quizzes.get_quizzes_with_owners(db, limit=100)
    
    return templates.TemplateResponse("quiz_list.html", {
        "request": request,
        "quizzes": quizzes,
        "current_user": current_user,
        "username": current_user.username
    })

@app.post("/quizzes/create", include_in_schema=False)
async def create_quiz_web(
    request: Request,
    title: str = Form(...),
    description: Optional[str] = Form(None),
    db: AsyncSession = Depends(database.get_db)
):
    token = request.cookies.get("token") or ""
    current_user = await get_user_from_token(token, db)
    if not current_user:
        return RedirectResponse(url="/login?error=Требуется%20авторизация", status_code=303)

    form = await request.form()
    questions_data = []
    q_index = 0
    while f"questions[{q_index}][text]" in form:
        q_text = form.get(f"questions[{q_index}][text]")
        if not q_text or not q_text.strip():
            q_index += 1
            continue
            
        options = []
        has_correct = False
        opt_index = 0
        while f"questions[{q_index}][options][{opt_index}][text]" in form:
            opt_text = form.get(f"questions[{q_index}][options][{opt_index}][text]")
            if opt_text and opt_text.strip():
                is_correct = f"questions[{q_index}][options][{opt_index}][is_correct]" in form
                if is_correct:
                    has_correct = True
                options.append({"text": opt_text.strip(), "is_correct": is_correct})
            opt_index += 1
            
        if options:
            if not has_correct:
                error = f"В вопросе {q_index + 1} не выбран правильный ответ"
                return RedirectResponse(url=f"/quizzes?error={error}", status_code=303)
            questions_data.append({"text": q_text.strip(), "options": options})
        q_index += 1

    if not questions_data:
        return RedirectResponse(url="/quizzes?error=Добавьте%20хотя%20бы%20один%20вопрос%20с%20вариантами", status_code=303)

    quiz_in = schemas.QuizCreateWithQuestions(
        title=title.strip(),
        description=description.strip() if description else None,
        questions=[
            schemas.QuestionCreate(text=q["text"], options=[
                schemas.OptionCreate(text=o["text"], is_correct=o["is_correct"]) for o in q["options"]
            ]) for q in questions_data
        ]
    )
    await crud.quizzes.create_quiz_with_questions(db, quiz_in, current_user.id)
    return RedirectResponse(url="/quizzes?success=Тест%20успешно%20создан", status_code=303)


@app.post(
    "/auth/register",
    response_model=schemas.UserResponse,
    summary="📄 Регистрация нового пользователя",
    description="Создаёт нового пользователя. Имя должно быть уникальным.",
    tags=["🔐 Аутентификация"]
)
async def register(user: schemas.UserCreate, db: AsyncSession = Depends(database.get_db)):
    db_user = await crud.users.get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Пользователь с таким именем уже существует")
    if len(user.password.encode('utf-8')) > 72:
        raise HTTPException(status_code=422, detail="Пароль не может быть длиннее 72 байт")
    hashed_pw = auth.get_password_hash(user.password)
    new_user = models.User(username=user.username, hashed_password=hashed_pw)
    await crud.users.create_user(db, new_user)
    return {"username": user.username}

@app.post(
    "/auth/token",
    response_model=schemas.Token,
    summary="🔑 Получить JWT-токен",
    description="Обменяйте имя пользователя и пароль на временный JWT-токен (действует 30 минут).",
    tags=["🔐 Аутентификация"]
)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: AsyncSession = Depends(database.get_db)
):
    user = await auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post(
    "/quizzes/",
    response_model=schemas.QuizOutFull,
    summary="➕ Создать тест с вопросами",
    description="Создаёт тест с вопросами и вариантами ответов.",
    tags=["📝 Тесты (Quizzes)"]
)
async def create_quiz_api(
    quiz: schemas.QuizCreateWithQuestions,
    db: AsyncSession = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    return await crud.quizzes.create_quiz_with_questions(db, quiz, current_user.id)

@app.get("/quizzes/{quiz_id}/take", response_class=HTMLResponse, include_in_schema=False)
async def take_quiz_page(
    request: Request,
    quiz_id: int,
    db: AsyncSession = Depends(database.get_db)
):
    token = request.cookies.get("token") or ""
    current_user = await get_user_from_token(token, db)
    if not current_user:
        return RedirectResponse(url="/login?error=Требуется%20авторизация", status_code=303)

    result = await db.execute(
        select(models.Quiz)
        .where(models.Quiz.id == quiz_id)
        .options(
            selectinload(models.Quiz.owner),  
            selectinload(models.Quiz.questions).selectinload(models.Question.options)
        )
    )
    quiz = result.scalars().first()
    if not quiz:
        return RedirectResponse(url="/quizzes?error=Тест%20не%20найден", status_code=303)
    
    return templates.TemplateResponse("take_quiz.html", {
        "request": request,
        "quiz": quiz,
        "current_user": current_user  
    })

@app.post("/quizzes/{quiz_id}/submit", include_in_schema=False)
async def submit_quiz(
    request: Request,
    quiz_id: int,
    db: AsyncSession = Depends(database.get_db)
):
    token = request.cookies.get("token") or ""
    current_user = await get_user_from_token(token, db)
    if not current_user:
        return RedirectResponse(url="/login?error=Требуется%20авторизация", status_code=303)

    form = await request.form()
    answers = {}
    for key, value in form.items():
        if key.startswith("answers[") and key.endswith("]"):
            try:
                q_id = int(key[8:-1])
                answers[q_id] = int(value)
            except (ValueError, TypeError):
                continue

    result = await db.execute(
        select(models.Option)
        .join(models.Question)
        .where(models.Question.quiz_id == quiz_id)
        .where(models.Option.is_correct == True)
    )
    correct_options = {opt.question_id: opt.id for opt in result.scalars()}

    score = 0
    total = len(correct_options)
    for q_id, selected_opt_id in answers.items():
        if correct_options.get(q_id) == selected_opt_id:
            score += 1

    return templates.TemplateResponse("quiz_result.html", {
        "request": request,
        "score": score,
        "total": total,
        "percentage": round(score / total * 100) if total > 0 else 0
    })

@app.get("/profile", response_class=HTMLResponse, include_in_schema=False)
async def profile_page(
    request: Request,
    db: AsyncSession = Depends(database.get_db)
):
    token = request.cookies.get("token") or ""
    current_user = await get_user_from_token(token, db)
    if not current_user:
        return RedirectResponse(url="/login?error=Требуется%20авторизация", status_code=303)
    
    # Отладка: проверяем, загружены ли вопросы
    quizzes = await crud.quizzes.get_user_quizzes(db, current_user.id)
    for quiz in quizzes:
        await db.refresh(quiz, ['questions'])
    
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "username": current_user.username,
        "user": current_user,
        "quizzes": quizzes
    })

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception):
    return templates.TemplateResponse(
        "404.html",
        {"request": request},
        status_code=404
    )

@app.post("/quizzes/{quiz_id}/delete", include_in_schema=False)
async def delete_quiz_web(
    request: Request,
    quiz_id: int,
    db: AsyncSession = Depends(database.get_db)
):
    token = request.cookies.get("token") or ""
    current_user = await get_user_from_token(token, db)
    if not current_user:
        return RedirectResponse(url="/login?error=Требуется%20авторизация", status_code=303)

    quiz = await crud.quizzes.get_quiz(db, quiz_id)
    if not quiz or quiz.owner_id != current_user.id:
        return RedirectResponse(url="/quizzes?error=Тест%20не%20найден%20или%20доступ%20запрещён", status_code=303)

    success = await crud.quizzes.delete_quiz(db, quiz_id)
    if not success:
        return RedirectResponse(url="/quizzes?error=Не%20удалось%20удалить%20тест", status_code=303)

    return RedirectResponse(url="/quizzes?success=Тест%20успешно%20удалён", status_code=303)

# Админка

def verify_admin_password(password: str) -> bool:
    """Простая проверка пароля администратора"""
    return password == ADMIN_PASSWORD

@app.get("/admin/login", response_class=HTMLResponse, include_in_schema=False)
async def admin_login_page(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse("admin/login.html", {"request": request, "error": error})

@app.post("/admin/login", response_class=HTMLResponse, include_in_schema=False)
async def admin_login(request: Request, password: str = Form(...)):
    if password == ADMIN_PASSWORD:
        response = RedirectResponse(url="/admin/users", status_code=303)
        response.set_cookie(key="admin_token", value="admin_session", httponly=False, max_age=3600)
        return response
    else:
        return RedirectResponse(url="/admin/login?error=Неверный%20пароль", status_code=303)

def check_admin_auth(request: Request):
    """Проверяет, авторизован ли админ"""
    admin_token = request.cookies.get("admin_token")
    if admin_token != "admin_session":
        raise HTTPException(status_code=403, detail="Доступ запрещен")

@app.get("/admin/users", response_class=HTMLResponse, include_in_schema=False)
async def admin_users_page(request: Request, db: AsyncSession = Depends(database.get_db)):
    check_admin_auth(request)
    users = await crud.users.get_all_users(db, limit=100)
    for user in users:
        quizzes_count = await db.execute(
            select(models.Quiz).where(models.Quiz.owner_id == user.id)
        )
        user.quizzes_count = len(quizzes_count.scalars().all())
    return templates.TemplateResponse("admin/users.html", {"request": request, "users": users})

@app.post("/admin/users/delete/{user_id}", include_in_schema=False)
async def admin_delete_user(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(database.get_db)
):
    check_admin_auth(request)
    success = await crud.users.delete_user(db, user_id)
    if not success:
        return RedirectResponse(url="/admin/users?error=Пользователь%20не%20найден", status_code=303)
    return RedirectResponse(url="/admin/users?success=Пользователь%20успешно%20удален", status_code=303)

@app.get("/admin/quizzes", response_class=HTMLResponse, include_in_schema=False)
async def admin_quizzes_page(request: Request, db: AsyncSession = Depends(database.get_db)):
    check_admin_auth(request)
    quizzes = await crud.quizzes.get_all_quizzes_with_users(db, limit=100)
    
    return templates.TemplateResponse("admin/quizzes.html", {"request": request, "quizzes": quizzes})

@app.post("/admin/quizzes/delete/{quiz_id}", include_in_schema=False)
async def admin_delete_quiz(
    request: Request,
    quiz_id: int,
    db: AsyncSession = Depends(database.get_db)
):
    check_admin_auth(request)
    success = await crud.quizzes.delete_quiz(db, quiz_id)
    if not success:
        return RedirectResponse(url="/admin/quizzes?error=Тест%20не%20найден", status_code=303)
    return RedirectResponse(url="/admin/quizzes?success=Тест%20успешно%20удален", status_code=303)

@app.get("/admin/logout", include_in_schema=False)
async def admin_logout():
    response = RedirectResponse(url="/admin/login", status_code=303)
    response.set_cookie(key="admin_token", value="", max_age=0)
    return response