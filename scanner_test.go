package main

import "testing"

func TestDirectPasswordInLog(t *testing.T) {
	code := "def f():\n    logger.info(f\"pwd: {user.password}\")\n"
	findings := Scan("test.py", code)
	if len(findings) == 0 {
		t.Fatal("expected finding for password in log")
	}
	if findings[0].Sink != "log" {
		t.Errorf("expected sink=log, got %s", findings[0].Sink)
	}
	if findings[0].Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
}

func TestTaintedEnvVarInResponse(t *testing.T) {
	code := "def f():\n    secret = os.environ[\"KEY\"]\n    return jsonify({\"k\": secret})\n"
	findings := Scan("test.py", code)
	found := false
	for _, f := range findings {
		if f.Sink == "http-response" && f.Variable == "secret" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected tainted 'secret' in http-response")
	}
}

func TestCleanCodeNoFindings(t *testing.T) {
	code := "def f():\n    name = get_name()\n    return jsonify({\"name\": name})\n"
	findings := Scan("clean.py", code)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestPasswordHashInException(t *testing.T) {
	code := "def f():\n    pwd = user.password_hash\n    raise ValueError(f\"bad: {pwd}\")\n"
	findings := Scan("test.py", code)
	if len(findings) == 0 {
		t.Fatal("expected finding for password_hash in exception")
	}
	if findings[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestCreditCardInPrint(t *testing.T) {
	code := "def f():\n    cc = order.credit_card\n    print(f\"card: {cc}\")\n"
	findings := Scan("test.py", code)
	if len(findings) == 0 {
		t.Fatal("expected finding for credit_card in print")
	}
	if findings[0].Source != "credit_card" {
		t.Errorf("expected source=credit_card, got %s", findings[0].Source)
	}
}

func TestEnvVarInLog(t *testing.T) {
	code := "def f():\n    key = os.getenv(\"DB_PASS\")\n    logging.error(f\"conn: {key}\")\n"
	findings := Scan("test.py", code)
	if len(findings) == 0 {
		t.Fatal("expected finding for env-var in log")
	}
	if findings[0].Source != "env-var" {
		t.Errorf("expected source=env-var, got %s", findings[0].Source)
	}
}
