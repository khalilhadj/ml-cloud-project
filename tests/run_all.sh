#!/usr/bin/env bash

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="$ROOT/.venv/bin/python"

if [ ! -x "$PYTHON" ]; then
    echo "ERREUR : environnement virtuel .venv introuvable."
    exit 1
fi

TESTS=(
    test_detector.py
    test_grouping.py
    test_dashboard.py
    test_dashboard2.py
    test_storage.py
    test_models_sync.py
    test_retrain.py
    test_scheduler.py
)

TOTAL=0
PASSED=0
FAILED=0

echo "===================================="
echo "   TESTS AUTOMATIQUES DU PROJET"
echo "===================================="

for TEST in "${TESTS[@]}"; do
    TOTAL=$((TOTAL + 1))
    echo ""
    echo "===== $TEST ====="

    if "$PYTHON" "tests/$TEST"; then
        echo "[OK] $TEST"
        PASSED=$((PASSED + 1))
    else
        echo "[ECHEC] $TEST"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "===================================="
echo "         BILAN GENERAL"
echo "===================================="
echo "Tests exécutés : $TOTAL"
echo "Réussis        : $PASSED"
echo "Échoués        : $FAILED"

if [ "$FAILED" -eq 0 ]; then
    echo "RESULTAT : TOUS LES TESTS SONT REUSSIS"
    exit 0
else
    echo "RESULTAT : CERTAINS TESTS ONT ECHOUE"
    exit 1
fi
