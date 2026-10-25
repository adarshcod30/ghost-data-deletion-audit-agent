import pytest

from ghostaudit.classifier import baseline_authorizes_deletion as decide

DELETION = [
    "Please delete my account and all my personal data.",
    "Je demande la suppression définitive du compte associé à cette adresse e-mail.",
    "Solicito a exclusão permanente da conta associada a este e-mail.",
    "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.",
    "このメールアドレスに関連するアカウントの完全な削除を依頼します。",
    "I'm deleting my account. You can keep anonymous statistics, but nothing in analytics should still point back to me.",
    "My account page is gone, but my old profile still appears when I search for it. Can you remove that search result too?",
]
OTHER = [
    "My surname is misspelled on the account. Can you correct it without removing any of my records?",
    "Please remove me from marketing lists only. I still want receipts and service messages for this account.",
    "Could you send me a copy of the information held on my account? I still use it, so please don't delete or change anything.",
    "I can't access my profile and need help resetting the login. Do not close the account.",
    "I'd like to download my account information in a portable format. Please keep the account as it is.",
    "Can you reset my password? I got locked out. I do not want the account closed.",
]


@pytest.mark.parametrize("text", DELETION)
def test_deletion_requests_including_non_english_ones(text):
    assert decide(text)[0] is True


@pytest.mark.parametrize("text", OTHER)
def test_other_requests_are_not_deletion(text):
    assert decide(text)[0] is False


def test_default_is_deletion_and_reason_is_reported():
    ok, why = decide("Some text in a language with no keyword at all")
    assert ok is True and why


def test_real_data_has_nine_non_deletion_texts_and_all_samples_are_deletion(dataset):
    assert all(decide(r.request_text)[0] for r in dataset.sample_requests)
    assert sum(1 for r in dataset.requests if not decide(r.request_text)[0]) == 10
