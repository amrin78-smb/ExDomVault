import pytest

from app.result_upload import (
    MAX_OBSERVATIONS_PER_BATCH,
    MAX_TARGETS_PER_BATCH,
    ResultUploader,
    make_result_id,
)

JOB = "6f1f8f7e-1d1b-4d55-8a0e-0d3f6a1b2c3d"


class RecordingApi:
    def __init__(self):
        self.calls = []

    def results(self, job_id, attempt, result_id, targets, observations, complete):
        self.calls.append(
            {
                "jobId": job_id,
                "attempt": attempt,
                "resultId": result_id,
                "targets": list(targets),
                "observations": list(observations),
                "complete": complete,
            }
        )
        return {"accepted": True, "status": "running"}


def obs(i: int) -> dict:
    return {"kind": "dns", "targetId": JOB, "values": [str(i)]}


def test_result_id_is_stable_and_valid():
    assert make_result_id(JOB, 2, 7) == f"{JOB}-2-0007"
    assert make_result_id(JOB, 2, 7) == make_result_id(JOB, 2, 7)


def test_batches_respect_observation_and_target_limits():
    api = RecordingApi()
    up = ResultUploader(api, JOB, 1)
    for i in range(MAX_OBSERVATIONS_PER_BATCH + 10):
        up.add_observation(obs(i))
    for i in range(MAX_TARGETS_PER_BATCH + 5):
        up.add_target(f"{i:08d}-0000-4000-8000-000000000000", "succeeded")
    up.finish()
    assert all(len(c["observations"]) <= MAX_OBSERVATIONS_PER_BATCH for c in api.calls)
    assert all(len(c["targets"]) <= MAX_TARGETS_PER_BATCH for c in api.calls)
    assert sum(len(c["observations"]) for c in api.calls) == MAX_OBSERVATIONS_PER_BATCH + 10
    assert sum(len(c["targets"]) for c in api.calls) == MAX_TARGETS_PER_BATCH + 5
    assert [c["complete"] for c in api.calls] == [False] * (len(api.calls) - 1) + [True]
    ids = [c["resultId"] for c in api.calls]
    assert len(set(ids)) == len(ids)


def test_batches_respect_byte_budget():
    api = RecordingApi()
    up = ResultUploader(api, JOB, 1)
    for _ in range(300):
        up.add_observation({"kind": "dns", "values": ["x" * 4000]})
    up.finish()
    assert len(api.calls) >= 2


def test_empty_final_batch_is_still_sent_and_cannot_repeat():
    api = RecordingApi()
    up = ResultUploader(api, JOB, 1)
    up.finish()
    assert api.calls == [
        {
            "jobId": JOB,
            "attempt": 1,
            "resultId": f"{JOB}-1-0000",
            "targets": [],
            "observations": [],
            "complete": True,
        }
    ]
    with pytest.raises(RuntimeError):
        up.finish()


def test_failed_target_carries_error_code():
    api = RecordingApi()
    up = ResultUploader(api, JOB, 1)
    up.add_target_result("t1", "failed", [obs(1)], "target_timeout")
    up.finish()
    assert api.calls[0]["targets"] == [
        {"targetId": "t1", "status": "failed", "errorCode": "target_timeout"}
    ]
