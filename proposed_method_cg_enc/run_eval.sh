#!/bin/bash
echo "========================================="
echo " Starting NDN Upload Evaluation..."
echo "========================================="

# 古いコンテナ等のクリーンアップ
docker-compose down -v > /dev/null 2>&1

echo "[1/3] Building and running containers..."
docker-compose up --build --abort-on-container-exit

echo "[2/3] Extracting and sorting logs..."
docker-compose logs --no-color > raw_output.log 2>&1

# タイムスタンプ行のみを抽出して秒順にソート
grep "^\[" raw_output.log | sort > sorted_logs.txt

echo "[3/3] Displaying time-ordered logs:"
echo ""
echo "------------------------------------------------------------------------"
cat sorted_logs.txt
echo "------------------------------------------------------------------------"
echo ""
echo "========================================="
echo " Evaluation Complete! (Logs are also saved in 'sorted_logs.txt')"
echo "========================================="
echo ""
echo ">>> UPLOAD COMPLETION TIME RESULT <<<"
grep "Upload Completion Time" raw_output.log || echo "Result not found. Check logs."
echo "========================================="
