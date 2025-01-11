import os
import threading
from dotenv import load_dotenv
from fastapi import FastAPI, File, UploadFile, HTTPException, Form, Depends, Security
from fastapi.security import APIKeyHeader
from PIL import Image, ImageOps, ImageDraw
import io
import pyclamd
from fastapi.responses import JSONResponse
import random
import string
import paramiko
from starlette.concurrency import run_in_threadpool
import aiofiles
from fastapi.middleware.cors import CORSMiddleware
import aiohttp
import re
from fastapi.responses import Response

# Загрузка переменных из .env
load_dotenv()

app = FastAPI(title="Image Processor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = os.getenv("UPLOAD_DIR")  # директория на сервере с апи
LOCAL_SERVER_DOMAIN = os.getenv("LOCAL_SERVER_DOMAIN")  # домен сервера
REMOTE_SERVER = os.getenv("REMOTE_SERVER")  # ip бэкап сервера
REMOTE_PORT = os.getenv("REMOTE_PORT")  # ip бэкап сервера
REMOTE_USER = os.getenv("REMOTE_USER")  # пользователь бэкап сервера
REMOTE_PASSWORD = os.getenv("REMOTE_PASSWORD")  # пользователь бэкап сервера
REMOTE_DIR = os.getenv("REMOTE_DIR")  # директория на бэкап сервере
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH")  # ключ к бэкап серверу
CLAMD_HOST = os.getenv("CLAMD_HOST")  # хост антивируса
CLAMD_PORT = int(os.getenv("CLAMD_PORT"))  # порт антивируса
API_SECRET = os.getenv("API_SECRET")  # секретный ключ для авторизации
REMOTE_IMAGE_BASE_URL = os.getenv(
    "REMOTE_IMAGE_BASE_URL", "https://xumm.app"
)  # базовый URL для запроса картинок

# Проверка, что директория для загрузки существует
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Инициализация локального хранилища для ClamAV
from threading import local

_thread_local = local()

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)


async def get_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Проверка API ключа
    """
    if not api_key or api_key != API_SECRET:
        raise HTTPException(
            status_code=401,
            detail="Неверный API ключ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return api_key


# Функция отправки файла на удалённый сервер через SCP
def upload_to_remote_server(local_file_path, remote_file_name):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            REMOTE_SERVER,
            port=int(REMOTE_PORT),
            username=REMOTE_USER,
            password=REMOTE_PASSWORD,
            timeout=10,
        )

        with ssh.open_sftp() as sftp:
            remote_path = os.path.join(REMOTE_DIR, remote_file_name)
            sftp.put(local_file_path, remote_path)

        ssh.close()
    except Exception as e:
        print(f"Ошибка при отправке на удалённый сервер: {e}")


# Функция для получения clamd клиента (с переиспользованием)
def get_clamd():
    if not hasattr(_thread_local, "clamd"):
        _thread_local.clamd = pyclamd.ClamdNetworkSocket(
            host=CLAMD_HOST, port=CLAMD_PORT
        )
    return _thread_local.clamd


# Функция для проверки на вирусы
async def check_for_viruses(file_content: bytes):
    await run_in_threadpool(_check_for_viruses_sync, file_content)


def _check_for_viruses_sync(file_content: bytes):
    cd = get_clamd()
    if not cd.ping():
        raise HTTPException(status_code=500, detail="Служба ClamAV недоступна")
    scan_result = cd.scan_stream(file_content)
    if scan_result:
        raise HTTPException(status_code=400, detail="Обнаружен вирус в файле")


# Функция сжатия изображения
def compress_image(
    image: Image.Image, target_size_kb: int, output_format: str
) -> io.BytesIO:
    import io
    from PIL import Image

    buffer = io.BytesIO()
    target_size_bytes = target_size_kb * 1024

    if output_format.upper() == "JPEG":
        quality = 90
        while True:
            buffer.seek(0)
            buffer.truncate(0)
            image.save(buffer, format=output_format, quality=quality)
            size = buffer.tell()
            if size <= target_size_bytes or quality <= 10:
                break
            quality -= 10
    elif output_format.upper() == "PNG":
        if image.mode == "RGBA":
            quantized_image = image.quantize(method=Image.Quantize.LIBIMAGEQUANT)
        else:
            quantized_image = image.quantize(
                colors=256, method=Image.Quantize.MEDIANCUT
            )

        buffer.seek(0)
        buffer.truncate(0)
        quantized_image.save(buffer, format=output_format, optimize=True)
        size = buffer.tell()

        if size <= target_size_bytes:
            buffer.seek(0)
            return buffer

        current_width, current_height = image.size
        scaling_factor = (target_size_bytes / size) ** 0.5
        new_width = max(1, int(current_width * scaling_factor))
        new_height = max(1, int(current_height * scaling_factor))
        resized_image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)

        if resized_image.mode != "RGBA":
            quantized_image = resized_image.quantize(
                colors=128, method=Image.Quantize.MEDIANCUT
            )
        else:
            quantized_image = resized_image.quantize(
                method=Image.Quantize.LIBIMAGEQUANT
            )

        buffer.seek(0)
        buffer.truncate(0)
        quantized_image.save(buffer, format=output_format, optimize=True)
        size = buffer.tell()

        if size <= target_size_bytes:
            buffer.seek(0)
            return buffer
    else:
        image.save(buffer, format=output_format)

    buffer.seek(0)
    return buffer


# Функция для генерации имени файла с уникальностью и ограничением на 8 символов
def generate_filename(extension: str, prefix: str) -> str:
    chars = string.ascii_letters + string.digits  # base62
    max_attempts = 5  # Ограничиваем число попыток
    for _ in range(max_attempts):
        random_string = "".join(random.choices(chars, k=5))
        filename = f"{prefix}{random_string}{extension}"  # Общая длина должна быть <=8
        local_file_path = os.path.join(UPLOAD_DIR, filename)
        if not os.path.exists(local_file_path):
            return filename
    raise HTTPException(
        status_code=500, detail="Не удалось создать уникальное имя файла"
    )


# Функция обработки логотипа
def process_logo_image(content: bytes, make_round: bool = True) -> io.BytesIO:
    image = Image.open(io.BytesIO(content))

    if make_round:
        # Обрезка до круга
        image = ImageOps.fit(
            image, (min(image.size), min(image.size)), centering=(0.5, 0.5)
        )

        # Создание круглой маски
        mask = Image.new("L", image.size, 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0) + image.size, fill=255)

        # Преобразование изображения в режим RGBA
        image = image.convert("RGBA")

        # Создание изображения с прозрачным фоном
        transparent_image = Image.new("RGBA", image.size)
        transparent_image.paste(image, (0, 0), mask=mask)
        image = transparent_image

    # Сжатие изображения
    compressed_image = compress_image(image, 100, "WEBP")
    return compressed_image


# Функция обработки баннера
def process_banner_image(content: bytes) -> io.BytesIO:
    image = Image.open(io.BytesIO(content))
    image = image.convert("RGB")

    # Сжатие изображения
    compressed_image = compress_image(image, 100, "JPEG")

    return compressed_image


# Эндпоинт для загрузки логотипа с кастомным именем
@app.post("/upload_logo_with_name/")
async def upload_logo_with_name(
    file: UploadFile = File(...),
    filename: str = Form(...),
    make_round: bool = Form(True),
    api_key: str = Depends(get_api_key),
):
    try:
        if file.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Недопустимый формат файла")

        content = await file.read()

        await check_for_viruses(content)

        compressed_image = await run_in_threadpool(
            process_logo_image, content, make_round
        )

        if not filename.lower().endswith(".webp"):
            filename = f"{filename}.webp"

        local_file_path = os.path.join(UPLOAD_DIR, filename)

        async with aiofiles.open(local_file_path, "wb") as f:
            await f.write(compressed_image.getvalue())

        threading.Thread(
            target=upload_to_remote_server, args=(local_file_path, filename)
        ).start()

        local_file_url = f"https://{LOCAL_SERVER_DOMAIN}/u/{filename}"
        return JSONResponse(content={"url": local_file_url})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при обработке файла: {e}")


# Эндпоинт для переименования файла
@app.post("/rename_file/")
async def rename_file(
    old_name: str = Form(...),
    new_name: str = Form(...),
    api_key: str = Depends(get_api_key),
):
    try:
        old_path = os.path.join(UPLOAD_DIR, old_name)
        new_path = os.path.join(UPLOAD_DIR, new_name)

        # Проверяем существование старого файла
        if not os.path.exists(old_path):
            return JSONResponse(content={"message": "Исходный файл не найден"})

        # Проверяем существование нового имени
        if os.path.exists(new_path):
            return JSONResponse(
                content={"message": "Файл с новым именем уже существует"}
            )

        # Переименовываем файл
        os.rename(old_path, new_path)

        # Отправляем на бэкап сервер с новым именем
        threading.Thread(
            target=upload_to_remote_server, args=(new_path, new_name)
        ).start()

        new_url = f"https://{LOCAL_SERVER_DOMAIN}/u/{new_name}"
        return JSONResponse(content={"url": new_url})

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при переименовании файла: {e}"
        )


# Эндпоинт для загрузки логотипа
@app.post("/upload_logo/")
async def upload_logo(file: UploadFile = File(...)):
    try:
        if file.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Недопустимый формат файла")

        content = await file.read()

        # Проверка на вирусы асинхронно
        await check_for_viruses(content)

        # Обработка изображения
        compressed_image = await run_in_threadpool(process_logo_image, content)

        # Генерация имени файла
        file_name = generate_filename(".png", "l")
        local_file_path = os.path.join(UPLOAD_DIR, file_name)

        # Сохранение файла
        async with aiofiles.open(local_file_path, "wb") as f:
            await f.write(compressed_image.getvalue())
        threading.Thread(
            target=upload_to_remote_server, args=(local_file_path, file_name)
        ).start()
        # Генерация ссылки на файл
        local_file_url = f"https://{LOCAL_SERVER_DOMAIN}/u/{file_name}"

        return JSONResponse(content={"url": local_file_url})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при обработке файла: {e}")


# Эндпоинт для загрузки баннера
@app.post("/upload_banner/")
async def upload_banner(file: UploadFile = File(...)):
    try:
        if file.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Недопустимый формат файла")

        content = await file.read()

        # Проверка на вирусы
        await check_for_viruses(content)

        # Обработка изображения
        compressed_image = await run_in_threadpool(process_banner_image, content)

        # Генерация имени файла
        file_name = generate_filename(".jpg", "b")
        local_file_path = os.path.join(UPLOAD_DIR, file_name)
        # Сохранение файла
        async with aiofiles.open(local_file_path, "wb") as f:
            await f.write(compressed_image.getvalue())

        threading.Thread(
            target=upload_to_remote_server, args=(local_file_path, file_name)
        ).start()
        # Генерация ссылки на файл
        local_file_url = f"https://{LOCAL_SERVER_DOMAIN}/u/{file_name}"

        return JSONResponse(content={"url": local_file_url})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при обработке файла: {e}")


async def fetch_and_convert_image(url: str, save_path: str) -> bytes:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status != 200:
                raise HTTPException(
                    status_code=404, detail="Image not found on remote server"
                )
            content = await response.read()
            image = Image.open(io.BytesIO(content))

            if image.mode == "RGBA":
                bg = Image.new("RGBA", image.size, (255, 255, 255, 255))
                bg.paste(image, mask=image.split()[3])
                image = bg

            output = io.BytesIO()
            image.save(output, format="WEBP", quality=95, method=6)

            webp_content = output.getvalue()

            async with aiofiles.open(save_path, "wb") as f:
                await f.write(webp_content)

            return webp_content


@app.get("/u/{filename}")
async def get_image(filename: str):
    local_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(local_path):
        async with aiofiles.open(local_path, 'rb') as f:
            content = await f.read()
        return Response(content=content, media_type="image/webp")
    parts = filename.split('_', 1) 
    base_name = parts[0]
    base_name = os.path.splitext(base_name)[0]
    if not base_name:
        raise HTTPException(status_code=404, detail="Invalid filename")
    remote_url = f"{REMOTE_IMAGE_BASE_URL}/avatar/{base_name}_250_20.png"
    try:
        content = await fetch_and_convert_image(remote_url, local_path)
        return Response(content=content, media_type="image/webp")
    except Exception as e:
        raise HTTPException(status_code=404, detail="Image not found")
