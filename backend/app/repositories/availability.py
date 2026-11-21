"""Consultas dos exercícios de disponibilidade vinculados ao ativo."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import AvailabilityExercise, AvailabilitySample, AvailabilitySignal


def list_exercises(db: Session, asset_id: str, limit: int = 10) -> list[AvailabilityExercise]:
    return list(
        db.scalars(
            select(AvailabilityExercise)
            .where(AvailabilityExercise.asset_id == asset_id)
            .order_by(AvailabilityExercise.started_at.desc(), AvailabilityExercise.id.desc())
            .limit(limit)
        )
    )


def find_exercise(db: Session, asset_id: str, exercise_id: str) -> AvailabilityExercise | None:
    return db.scalar(
        select(AvailabilityExercise).where(
            AvailabilityExercise.asset_id == asset_id, AvailabilityExercise.id == exercise_id
        )
    )


def find_running_exercises(db: Session, asset_id: str) -> list[AvailabilityExercise]:
    return list(
        db.scalars(
            select(AvailabilityExercise).where(
                AvailabilityExercise.asset_id == asset_id, AvailabilityExercise.status == "RUNNING"
            )
        )
    )


def list_samples(db: Session, exercise_id: str) -> list[AvailabilitySample]:
    return list(
        db.scalars(
            select(AvailabilitySample)
            .where(AvailabilitySample.exercise_id == exercise_id)
            .order_by(AvailabilitySample.seq)
        )
    )


def list_signals(db: Session, exercise_id: str) -> list[AvailabilitySignal]:
    return list(
        db.scalars(
            select(AvailabilitySignal)
            .where(AvailabilitySignal.exercise_id == exercise_id)
            .order_by(AvailabilitySignal.offset_ms, AvailabilitySignal.created_at, AvailabilitySignal.id)
        )
    )
