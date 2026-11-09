from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "postgresql+psycopg://scanner:scanner@localhost:5432/scanner"
    SECRET_KEY: str = "change-me"

    DIRSEARCH_PATH: str = "/home/kali/Downloads/myscanner/dirsearch-master/dirsearch.py"
    DIRSEARCH_DIR: str = "/home/kali/Downloads/myscanner/dirsearch-master"
    NUCLEI_BIN: str = "/usr/local/bin/nuclei"

    # таймауты сканеров (сек), None = без лимита
    DIRSEARCH_TIMEOUT: int | None = None
    NUCLEI_TIMEOUT: int | None = None


settings = Settings()