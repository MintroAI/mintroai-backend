"""
User repository using SQLAlchemy ORM
"""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from src.core.service.auth.models.user import User, UserTier
from src.infra.models import UserModel
from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class UserRepository:
    """Repository for user database operations using SQLAlchemy ORM"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    def _model_to_entity(self, model: UserModel) -> User:
        """Convert SQLAlchemy model to Pydantic entity"""
        return User(
            id=model.id,
            wallet_address=model.wallet_address,
            protocol=model.protocol,
            first_login_at=model.first_login_at,
            last_login_at=model.last_login_at,
            login_count=model.login_count,
            challenge_count=model.challenge_count,
            user_tier=UserTier(model.user_tier),
            created_at=model.created_at,
            updated_at=model.updated_at
        )
    
    async def get_or_create_user(
        self,
        wallet_address: str,
        protocol: str
    ) -> Optional[User]:
        """
        Get existing user or create new one using SQLAlchemy ORM
        
        Args:
            wallet_address: Wallet address
            protocol: Protocol type ('evm' or 'near')
            
        Returns:
            User object or None if operation fails
        """
        try:
            # Try to get existing user
            stmt = select(UserModel).where(
                UserModel.wallet_address == wallet_address.lower(),
                UserModel.protocol == protocol
            )
            result = await self.session.execute(stmt)
            user_model = result.scalar_one_or_none()
            
            if user_model:
                return self._model_to_entity(user_model)
            
            # Create new user
            now = datetime.now(timezone.utc)
            new_user = UserModel(
                wallet_address=wallet_address.lower(),
                protocol=protocol,
                first_login_at=now,
                last_login_at=now,
                login_count=0,
                challenge_count=0,
                user_tier=UserTier.FREE.value
            )
            
            self.session.add(new_user)
            await self.session.commit()
            await self.session.refresh(new_user)
            
            logger.info(
                "New user created in database",
                extra={
                    "wallet_address": wallet_address,
                    "protocol": protocol,
                    "user_id": str(new_user.id)
                }
            )
            
            return self._model_to_entity(new_user)
            
        except IntegrityError as e:
            await self.session.rollback()
            logger.warning(
                f"User already exists (race condition): {e}",
                extra={
                    "wallet_address": wallet_address,
                    "protocol": protocol
                }
            )
            # Try to get the user again
            stmt = select(UserModel).where(
                UserModel.wallet_address == wallet_address.lower(),
                UserModel.protocol == protocol
            )
            result = await self.session.execute(stmt)
            user_model = result.scalar_one_or_none()
            return self._model_to_entity(user_model) if user_model else None
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to get or create user",
                extra={
                    "wallet_address": wallet_address,
                    "protocol": protocol,
                    "error": str(e)
                }
            )
            return None
    
    async def update_user_challenge(
        self,
        wallet_address: str,
        protocol: str
    ) -> bool:
        """
        Update user challenge count using SQLAlchemy ORM
        
        Args:
            wallet_address: Wallet address
            protocol: Protocol type
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure user exists
            user = await self.get_or_create_user(wallet_address, protocol)
            if not user:
                return False
            
            # Update challenge count
            stmt = (
                update(UserModel)
                .where(
                    UserModel.wallet_address == wallet_address.lower(),
                    UserModel.protocol == protocol
                )
                .values(
                    challenge_count=UserModel.challenge_count + 1,
                    updated_at=datetime.now(timezone.utc)
                )
            )
            
            await self.session.execute(stmt)
            await self.session.commit()
            
            logger.debug(
                "User challenge count updated",
                extra={
                    "wallet_address": wallet_address,
                    "protocol": protocol
                }
            )
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to update user challenge count",
                extra={
                    "wallet_address": wallet_address,
                    "protocol": protocol,
                    "error": str(e)
                }
            )
            return False
    
    async def update_user_login(
        self,
        wallet_address: str,
        protocol: str
    ) -> bool:
        """
        Update user login information using SQLAlchemy ORM
        
        Args:
            wallet_address: Wallet address
            protocol: Protocol type
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure user exists
            user = await self.get_or_create_user(wallet_address, protocol)
            if not user:
                return False
            
            # Update login information
            stmt = (
                update(UserModel)
                .where(
                    UserModel.wallet_address == wallet_address.lower(),
                    UserModel.protocol == protocol
                )
                .values(
                    login_count=UserModel.login_count + 1,
                    last_login_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc)
                )
            )
            
            await self.session.execute(stmt)
            await self.session.commit()
            
            logger.info(
                "User login recorded in database",
                extra={
                    "wallet_address": wallet_address,
                    "protocol": protocol
                }
            )
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to update user login",
                extra={
                    "wallet_address": wallet_address,
                    "protocol": protocol,
                    "error": str(e)
                }
            )
            return False
    
    async def get_user_by_wallet(
        self,
        wallet_address: str,
        protocol: str
    ) -> Optional[User]:
        """
        Get user by wallet address and protocol using SQLAlchemy ORM
        
        Args:
            wallet_address: Wallet address
            protocol: Protocol type
            
        Returns:
            User object or None
        """
        try:
            stmt = select(UserModel).where(
                UserModel.wallet_address == wallet_address.lower(),
                UserModel.protocol == protocol
            )
            result = await self.session.execute(stmt)
            user_model = result.scalar_one_or_none()
            
            if not user_model:
                return None
            
            return self._model_to_entity(user_model)
            
        except Exception as e:
            logger.error(
                "Failed to get user by wallet",
                extra={
                    "wallet_address": wallet_address,
                    "protocol": protocol,
                    "error": str(e)
                }
            )
            return None
