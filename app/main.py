from fastapi import FastAPI
from app.database import engine, Base
from app.models import user as user_model
from app.models import token_blacklist as blacklist_model
from app.routers import auth
 
# Create all tables in PostgreSQL automatically
Base.metadata.create_all(bind=engine)
 
app = FastAPI(
    title='FastAPI Auth API',
    description='JWT Authentication with PostgreSQL',
    version='1.0.0'
)
 
# Register routers (like app.use('/auth', authRouter) in Express)
app.include_router(auth.router, prefix='/auth', tags=['Authentication'])

@app.get('/')
def root():
    return {'message': 'FastAPI Auth API is running'}
