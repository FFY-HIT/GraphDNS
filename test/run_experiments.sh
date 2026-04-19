#!/bin/bash
# ==============================================
# 完整性能测试脚本
# 测试多组记录数的性能
# ==============================================

# 配置参数
PROGRAM="./direct_verifier"
DATA_DIR="./census"

# 记录数配置数组
RECORD_COUNTS=(100000 200000 300000 400000 500000 
               600000 700000 800000 900000 1000000
               1500000 2000000 2500000 3000000 
               3500000 4000000 4500000 5000000
               6000000 7000000 8000000 9000000 10000000)

# 每组重复次数
REPEAT_TIMES=5

# 输出文件
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="performance_results_${TIMESTAMP}.csv"
SUMMARY_FILE="performance_summary_${TIMESTAMP}.csv"
LOG_FILE="performance_log_${TIMESTAMP}.txt"

# 日志函数
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

echo "=============================================="
log "开始性能测试"
log "程序: $PROGRAM"
log "数据目录: $DATA_DIR"
log "记录数组数: ${#RECORD_COUNTS[@]} 组"
log "每组重复: $REPEAT_TIMES 次"
log "输出文件: $RESULTS_FILE"
log "摘要文件: $SUMMARY_FILE"
log "日志文件: $LOG_FILE"
echo "=============================================="

# 检查程序是否存在
if [ ! -f "$PROGRAM" ]; then
    log "错误: 程序 $PROGRAM 不存在!"
    log "请先编译程序: g++ -O3 -fopenmp -std=c++17 -o direct_verifier your_source.cpp"
    exit 1
fi

# 检查数据目录是否存在
if [ ! -d "$DATA_DIR" ]; then
    log "错误: 数据目录 $DATA_DIR 不存在!"
    exit 1
fi

# 创建结果文件并写入表头
echo "max_records,run_num,load_time,verify_time,total_time" > "$RESULTS_FILE"

# 创建摘要文件并写入表头
echo "max_records,avg_load_time,avg_verify_time,avg_total_time,min_total_time,max_total_time" > "$SUMMARY_FILE"

# 计算总实验次数
TOTAL_EXPERIMENTS=$(( ${#RECORD_COUNTS[@]} * REPEAT_TIMES ))
log "总实验次数: $TOTAL_EXPERIMENTS"

# 记录总开始时间
TOTAL_START_TIME=$(date +%s)
EXPERIMENTS_COMPLETED=0

# 对每组记录数进行测试
for record_count in "${RECORD_COUNTS[@]}"; do
    log ""
    log "=================================================="
    log "测试记录数: $record_count"
    log "=================================================="
    
    # 存储当前组的结果
    CURRENT_LOAD_TIMES=()
    CURRENT_VERIFY_TIMES=()
    CURRENT_TOTAL_TIMES=()
    
    GROUP_START_TIME=$(date +%s)
    
    # 重复测试
    for ((run=1; run<=REPEAT_TIMES; run++)); do
        EXPERIMENTS_COMPLETED=$((EXPERIMENTS_COMPLETED + 1))
        
        log "运行 $run/$REPEAT_TIMES (总进度: $EXPERIMENTS_COMPLETED/$TOTAL_EXPERIMENTS)..."
        
        # 运行程序并捕获输出
        OUTPUT=$("$PROGRAM" "$DATA_DIR" "$record_count" 2>&1)
        
        # 从输出中提取时间信息
        LOAD_TIME=$(echo "$OUTPUT" | grep "Loaded" | grep -Eo "in [0-9.]+s" | grep -Eo "[0-9.]+" | head -1)
        VERIFY_TIME=$(echo "$OUTPUT" | grep "Verified" | grep -Eo "in [0-9.]+s" | grep -Eo "[0-9.]+" | head -1)
        
        # 如果提取成功，计算总和并存储
        if [ -n "$LOAD_TIME" ] && [ -n "$VERIFY_TIME" ]; then
            TOTAL_TIME=$(echo "$LOAD_TIME + $VERIFY_TIME" | bc)
            
            # 存储到数组（所有数据，包括第一次）
            CURRENT_LOAD_TIMES+=("$LOAD_TIME")
            CURRENT_VERIFY_TIMES+=("$VERIFY_TIME")
            CURRENT_TOTAL_TIMES+=("$TOTAL_TIME")
            
            # 写入结果文件（仍然记录所有运行）
            echo "$record_count,$run,$LOAD_TIME,$VERIFY_TIME,$TOTAL_TIME" >> "$RESULTS_FILE"
            
            log "  加载: ${LOAD_TIME}s, 验证: ${VERIFY_TIME}s, 总计: ${TOTAL_TIME}s"
        else
            log "  错误: 无法从输出中提取时间信息"
            # 显示相关输出行帮助调试
            echo "$OUTPUT" | grep -E "(Loaded|Verified|Will read)" >> "$LOG_FILE"
        fi
        
        # 计算并显示进度
        ELAPSED=$(( $(date +%s) - TOTAL_START_TIME ))
        AVG_TIME_PER_EXPERIMENT=$(echo "scale=2; $ELAPSED / $EXPERIMENTS_COMPLETED" | bc)
        REMAINING_EXPERIMENTS=$((TOTAL_EXPERIMENTS - EXPERIMENTS_COMPLETED))
        REMAINING_TIME=$(echo "$AVG_TIME_PER_EXPERIMENT * $REMAINING_EXPERIMENTS" | bc)
        
        PROGRESS_PERCENT=$((EXPERIMENTS_COMPLETED * 100 / TOTAL_EXPERIMENTS))
        
        # 转换时间为可读格式
        ELAPSED_READABLE=$(printf "%02d:%02d:%02d" $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))
        REMAINING_READABLE=$(printf "%02d:%02d:%02d" $((REMAINING_TIME/3600)) $(((REMAINING_TIME%3600)/60)) $((REMAINING_TIME%60)))
        
        log "  进度: $PROGRESS_PERCENT% | 已用: $ELAPSED_READABLE | 预计剩余: $REMAINING_READABLE"
    done

    # 计算当前组的统计信息
    if [ ${#CURRENT_TOTAL_TIMES[@]} -gt 0 ]; then
        log ""
        log "计算统计信息..."

        LOAD_SUM=0
        VERIFY_SUM=0
        TOTAL_SUM=0
        NUM_VALID_RUNS=${#CURRENT_TOTAL_TIMES[@]}

        MIN_TOTAL=${CURRENT_TOTAL_TIMES[0]}
        MAX_TOTAL=${CURRENT_TOTAL_TIMES[0]}

        for ((i=0; i<${#CURRENT_TOTAL_TIMES[@]}; i++)); do
            LOAD_SUM=$(echo "$LOAD_SUM + ${CURRENT_LOAD_TIMES[$i]}" | bc)
            VERIFY_SUM=$(echo "$VERIFY_SUM + ${CURRENT_VERIFY_TIMES[$i]}" | bc)
            TOTAL_SUM=$(echo "$TOTAL_SUM + ${CURRENT_TOTAL_TIMES[$i]}" | bc)

            if (( $(echo "${CURRENT_TOTAL_TIMES[$i]} < $MIN_TOTAL" | bc -l) )); then
                MIN_TOTAL=${CURRENT_TOTAL_TIMES[$i]}
            fi
            if (( $(echo "${CURRENT_TOTAL_TIMES[$i]} > $MAX_TOTAL" | bc -l) )); then
                MAX_TOTAL=${CURRENT_TOTAL_TIMES[$i]}
            fi
        done

        AVG_LOAD=$(echo "scale=4; $LOAD_SUM / $NUM_VALID_RUNS" | bc)
        AVG_VERIFY=$(echo "scale=4; $VERIFY_SUM / $NUM_VALID_RUNS" | bc)
        AVG_TOTAL=$(echo "scale=4; $TOTAL_SUM / $NUM_VALID_RUNS" | bc)

        GROUP_ELAPSED=$(( $(date +%s) - GROUP_START_TIME ))
        GROUP_ELAPSED_READABLE=$(printf "%02d:%02d:%02d" $((GROUP_ELAPSED/3600)) $(((GROUP_ELAPSED%3600)/60)) $((GROUP_ELAPSED%60)))

        log "组 $record_count 完成! 耗时: $GROUP_ELAPSED_READABLE"
        log "有效运行次数: $NUM_VALID_RUNS"
        log "平均加载时间: ${AVG_LOAD}s"
        log "平均验证时间: ${AVG_VERIFY}s"
        log "平均总时间: ${AVG_TOTAL}s"
        log "总时间范围: ${MIN_TOTAL}s - ${MAX_TOTAL}s"

        echo "$record_count,$AVG_LOAD,$AVG_VERIFY,$AVG_TOTAL,$MIN_TOTAL,$MAX_TOTAL" >> "$SUMMARY_FILE"
    else
        log "警告: 组 $record_count 没有有效数据，跳过统计"
    fi
done

# 计算总耗时
TOTAL_ELAPSED=$(( $(date +%s) - TOTAL_START_TIME ))
TOTAL_ELAPSED_READABLE=$(printf "%02d:%02d:%02d" $((TOTAL_ELAPSED/3600)) $(((TOTAL_ELAPSED%3600)/60)) $((TOTAL_ELAPSED%60)))

log ""
log "=============================================="
log "测试完成!"
log "总耗时: $TOTAL_ELAPSED_READABLE"
log "结果文件: $RESULTS_FILE"
log "摘要文件: $SUMMARY_FILE"
log "日志文件: $LOG_FILE"
log "=============================================="

# 生成最终报告
echo ""
echo "=============================================="
echo "最终报告"
echo "=============================================="
echo ""

# 显示摘要文件内容
if [ -f "$SUMMARY_FILE" ]; then
    echo "摘要统计 (每组平均值):"
    echo "------------------------------------------------------------"
    printf "%-12s %-12s %-12s %-12s %-12s %-12s\n" \
        "记录数" "平均加载(s)" "平均验证(s)" "平均总计(s)" "最小总计(s)" "最大总计(s)"
    echo "------------------------------------------------------------"
    
    # 读取摘要文件并显示
    tail -n +2 "$SUMMARY_FILE" | while IFS=',' read -r rec avg_load avg_verify avg_total min_total max_total; do
        printf "%-12s %-12.4f %-12.4f %-12.4f %-12.4f %-12.4f\n" \
            "$rec" "$avg_load" "$avg_verify" "$avg_total" "$min_total" "$max_total"
    done
    
    echo "------------------------------------------------------------"
    echo ""
    
    # 显示关键数据点
    echo "关键数据点:"
    echo "-----------"
    
    # 显示几个关键规模的性能
    KEY_POINTS=(10000 100000 500000 1000000 2000000 3000000 4000000)
    for point in "${KEY_POINTS[@]}"; do
        grep "^$point," "$SUMMARY_FILE" | while IFS=',' read -r rec avg_load avg_verify avg_total min_total max_total; do
            echo "$point 条记录:"
            echo "  加载时间: ${avg_load}s"
            echo "  验证时间: ${avg_verify}s"
            echo "  总时间: ${avg_total}s"
            echo "  时间范围: ${min_total}s - ${max_total}s"
            echo ""
        done
    done
fi

# 显示CSV文件位置
echo ""
echo "文件位置:"
echo "---------"
echo "详细结果: $(pwd)/$RESULTS_FILE"
echo "统计摘要: $(pwd)/$SUMMARY_FILE"
echo "运行日志: $(pwd)/$LOG_FILE"

# 创建简单的图表脚本（如果gnuplot可用）
if command -v gnuplot > /dev/null 2>&1; then
    echo ""
    echo "生成图表..."
    
    cat > plot_performance.gnuplot << EOF
set terminal pngcairo size 1200,800 enhanced font 'Arial,10'
set output 'performance_chart.png'
set multiplot layout 2,2 title "性能分析图表" font 'Arial,14'
# 图1: 总时间 vs 记录数
set title "总时间 vs 记录数"
set xlabel "记录数"
set ylabel "时间 (秒)"
set logscale x
set grid
plot '$SUMMARY_FILE' using 1:4 with linespoints lw 2 title '平均总时间'
# 图2: 加载时间和验证时间分解
set title "加载时间 vs 验证时间"
set xlabel "记录数"
set ylabel "时间 (秒)"
set logscale x
set grid
plot '$SUMMARY_FILE' using 1:2 with linespoints lw 2 title '加载时间', \
     '$SUMMARY_FILE' using 1:3 with linespoints lw 2 title '验证时间'
# 图3: 时间范围
set title "时间范围 (最小-最大)"
set xlabel "记录数"
set ylabel "时间 (秒)"
set logscale x
set grid
plot '$SUMMARY_FILE' using 1:5 with linespoints lw 2 title '最小时间', \
     '$SUMMARY_FILE' using 1:4 with linespoints lw 2 title '平均时间', \
     '$SUMMARY_FILE' using 1:6 with linespoints lw 2 title '最大时间'
# 图4: 加载验证比例
set title "加载/验证时间比例"
set xlabel "记录数"
set ylabel "比例"
set logscale x
set yrange [0:1]
set grid
plot '$SUMMARY_FILE' using 1:(\$2/\$4) with linespoints lw 2 title '加载比例', \
     '$SUMMARY_FILE' using 1:(\$3/\$4) with linespoints lw 2 title '验证比例'
unset multiplot
EOF
    
    gnuplot plot_performance.gnuplot
    echo "图表已保存为: $(pwd)/performance_chart.png"
else
    echo ""
    echo "提示: 安装 gnuplot 可以生成性能图表:"
    echo "  Ubuntu: sudo apt-get install gnuplot"
    echo "  Mac: brew install gnuplot"
    echo "  CentOS: sudo yum install gnuplot"
fi

echo ""
echo "=============================================="
echo "测试脚本执行完成!"
echo "=============================================="