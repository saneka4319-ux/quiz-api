from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.exceptions import RequestValidationError
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
from pydantic import ValidationError
from fastapi.exceptions import RequestValidationError

app = FastAPI(
    title="📚 Quiz API — Сервис создания и прохождения тестов",
    description="""
    🌐 Полноценный веб-API для создания, редактирования и прохождения интерактивных тестов.

    ### 🔐 Безопасность
    - Все операции с тестами и профилем требуют **авторизации через JWT**.
    - Токен выдаётся на **30 минут**.
    - Административные действия защищены отдельной сессией.

    ### 🚀 Как начать?
    1. Зарегистрируйтесь через `/auth/register` (или через веб-форму).
    2. Получите токен через `/auth/token`.
    3. Создавайте тесты, проходите их, просматривайте профиль!

    💡 **Примечание**: Веб-интерфейс доступен по корневому пути (`/`), но не отображается в этой документации.
    """,
    version="1.2.0",
    contact={
        "name": "kaer2",
        "url": "https://www.pythonanywhere.com",
    },
    license_info={
        "name": "MIT License",
    },
    docs_url="/docs",          # Swagger UI
    redoc_url="/redoc",        # ReDoc
    openapi_url="/openapi.json",
    openapi_tags=[
        {
            "name": "🔐 Аутентификация",
            "description": "Регистрация и получение JWT-токена для доступа к защищённым эндпоинтам.",
            "externalDocs": {
                "description": "Подробнее о JWT",
                "url": "https://jwt.io/introduction/"
            }
        },
        {
            "name": "📝 Тесты (Quizzes)",
            "description": "Создание, редактирование и управление вашими тестами. **Требуется авторизация.**",
        },
        {
            "name": "🌍 Публичные эндпоинты",
            "description": "Просмотр списка всех доступных тестов. **Не требует авторизации.**",
        },
        {
            "name": "👤 Профиль пользователя",
            "description": "Получение данных о текущем пользователе и его активности.",
        },
    ]
)

@app.exception_handler(ValidationError)
async def pydantic_validation_exception_handler(
    request: Request,
    exc: ValidationError
):
    return templates.TemplateResponse(
        "422.html",
        {
            "request": request,
            "errors": exc.errors(),
        },
        status_code=422
    )
@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(
    request: Request,
    exc: RequestValidationError
):
    return templates.TemplateResponse(
        "422.html",
        {
            "request": request,
            "errors": exc.errors(),
        },
        status_code=422
    )

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123" 

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

@app.on_event("startup")
async def startup():
    async with database.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
        
    async with database.async_session() as db:
        result = await db.execute(
            select(models.User).where(models.User.username == ADMIN_USERNAME)
        )
        admin = result.scalars().first()

        if not admin:
            hashed_password = auth.get_password_hash(ADMIN_PASSWORD)
            admin_user = models.User(
                username=ADMIN_USERNAME,
                hashed_password=hashed_password
            )
            db.add(admin_user)
            await db.commit()
            print("✅ Admin user created: admin / admin123")
        else:
            print("ℹ️ Admin user already exists")



async def get_user_from_token(token: str, db: AsyncSession):
    try:
        payload = auth.jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return await auth.get_user(db, username)
    except JWTError:
        return None


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return templates.TemplateResponse(
        "422.html",
        {
            "request": request,
            "errors": exc.errors()
        },
        status_code=422
    )

# === HTML Routes ===

@app.get(
    "/",
    response_class=HTMLResponse,
    tags=["🌍 Публичные эндпоинты"],
    summary="Главная страница",
    description="Перенаправляет пользователя на страницу входа или список тестов."
)
async def root_redirect(request: Request, db: AsyncSession = Depends(database.get_db)):
    token = request.cookies.get("token") or ""
    current_user = await get_user_from_token(token, db)
    if current_user:
        return RedirectResponse(url="/quizzes", status_code=status.HTTP_303_SEE_OTHER)
    else:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@app.get(
    "/login",
    response_class=HTMLResponse,
    tags=["🔐 Аутентификация"],
    summary="Страница входа",
    description="HTML-форма для входа пользователя."
)
async def login_page(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

@app.get(
    "/register",
    response_class=HTMLResponse,
    tags=["🔐 Аутентификация"],
    summary="Страница регистрации",
    description="HTML-форма для регистрации нового пользователя."
)
async def register_page(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse("register.html", {"request": request, "error": error})

@app.get(
    "/logout",
    tags=["🔐 Аутентификация"],
    summary="Выход из системы",
    description="Удаляет JWT-токен из cookies и завершает сессию."
)
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

@app.get(
    "/quizzes",
    response_class=HTMLResponse,
    tags=["📝 Тесты (Quizzes)"],
    summary="Список тестов",
    description="HTML-страница со списком всех доступных тестов."
)
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

@app.post(
    "/quizzes/create",
    tags=["📝 Тесты (Quizzes)"],
    summary="Создание теста (WEB)",
    description="Создание теста через HTML-форму."
)
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
            # ✅ ОБЯЗАТЕЛЬНАЯ ПРОВЕРКА: хотя бы 1 правильный ответ
            if not has_correct:
                error = f"В вопросе {q_index + 1} не выбран правильный ответ"
                return RedirectResponse(url=f"/quizzes?error={error}", status_code=303)
            questions_data.append({"text": q_text.strip(), "options": options})
        q_index += 1

    if not questions_data:
        return RedirectResponse(url="/quizzes?error=Добавьте%20хотя%20бы%20один%20вопрос%20с%20вариантами", status_code=303)

    # Создаём тест
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

# === API Routes ===

@app.post(
    "/auth/register",
    tags=["🔐 Аутентификация"],
    summary="Регистрация пользователя",
    description="Регистрирует нового пользователя через веб-форму."
)
async def register_web(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(database.get_db)
):
    user = schemas.UserCreate(username=username, password=password)

    db_user = await crud.users.get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=422, detail="Пользователь уже существует")

    hashed_pw = auth.get_password_hash(user.password)
    new_user = models.User(
        username=user.username,
        hashed_password=hashed_pw
    )

    await crud.users.create_user(db, new_user)

    return RedirectResponse("/login", status_code=303)

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
    tags=["📝 Тесты (Quizzes)"],
    summary="Создать тест (API)",
    description="Создаёт тест с вопросами и вариантами ответов через API."
)
async def create_quiz_api(
    quiz: schemas.QuizCreateWithQuestions,
    db: AsyncSession = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    return await crud.quizzes.create_quiz_with_questions(db, quiz, current_user.id)

@app.get(
    "/quizzes/{quiz_id}/take",
    response_class=HTMLResponse,
    tags=["📝 Тесты (Quizzes)"],
    summary="Прохождение теста",
    description="HTML-страница для прохождения выбранного теста."
)
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

@app.post(
    "/quizzes/{quiz_id}/submit",
    tags=["📝 Тесты (Quizzes)"],
    summary="Отправка ответов",
    description="Отправляет ответы пользователя и показывает результат."
)
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

@app.get(
    "/profile",
    response_class=HTMLResponse,
    tags=["👤 Профиль пользователя"],
    summary="Профиль пользователя",
    description="HTML-страница профиля текущего пользователя."
)
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

@app.get(
    "/admin/login",
    response_class=HTMLResponse,
    tags=["🛠 Админка"],
    summary="Вход администратора",
    description="HTML-страница входа в административную панель."
)
async def admin_login_page(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse("admin/login.html", {"request": request, "error": error})

@app.post(
    "/admin/login",
    tags=["🛠 Админка"],
    summary="Авторизация администратора",
    description="Проверка пароля администратора и создание сессии."
)
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

@app.get(
    "/admin/users",
    response_class=HTMLResponse,
    tags=["🛠 Админка"],
    summary="Пользователи",
    description="Список всех пользователей системы."
)
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

@app.get(
    "/admin/quizzes",
    response_class=HTMLResponse,
    tags=["🛠 Админка"],
    summary="Все тесты",
    description="Просмотр и управление всеми тестами в системе."
)
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

@app.get(
    "/admin/logout",
    tags=["🛠 Админка"],
    summary="Выход администратора",
    description="Завершает сессию администратора."
)
async def admin_logout():
    response = RedirectResponse(url="/admin/login", status_code=303)
    response.set_cookie(key="admin_token", value="", max_age=0)
    return response