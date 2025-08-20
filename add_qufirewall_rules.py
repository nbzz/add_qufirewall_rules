#!/usr/bin/env python3

import argparse
import csv
import json
import os
import sys
from typing import List, Dict, Any, Set, Tuple


def read_ip_list(ip_txt_path: str) -> List[str]:
    if not os.path.exists(ip_txt_path):
        raise FileNotFoundError(f"IP list file not found: {ip_txt_path}")
    ip_values: List[str] = []
    with open(ip_txt_path, "r", encoding="utf-8") as f:
        for line in f:
            value = line.strip()
            if not value:
                continue
            if value.startswith("#"):
                continue
            ip_values.append(value)
    return ip_values


def load_csv(csv_path: str) -> Tuple[List[str], List[List[str]]]:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        rows = list(reader)
        if not rows:
            raise ValueError("CSV is empty")
        header = rows[0]
        data_rows = rows[1:]
        return header, data_rows


def dump_csv(csv_path: str, header: List[str], rows: List[List[str]]) -> None:
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for row in rows:
            writer.writerow(row)


def parse_json_field(value: str) -> Any:
    if value is None or value == "":
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"Failed to parse JSON from CSV field. Error: {e}\nValue (truncated): {value[:2000]}"
        )


def dump_json_field(obj: Any) -> str:
    # Match spacing style in existing CSV JSON fields
    return json.dumps(obj, ensure_ascii=False, separators=(", ", ": "))


def build_allow_rule(src_ip: str, next_id: int) -> Dict[str, Any]:
    return {
        "enable": 1,
        "protocol": "Any",
        "permission": "Allow",
        "interface_warning": 0,
        "port_option": "Any",
        "src_ip": src_ip,
        "interface": "All",
        "display_name": "All",
        "id": next_id,
    }


def collect_existing_ids_and_src_ips(rules_list: List[Dict[str, Any]]) -> Tuple[int, Set[str]]:
    max_id = 0
    src_ips: Set[str] = set()
    for item in rules_list:
        if isinstance(item, dict):
            if "id" in item:
                try:
                    max_id = max(max_id, int(item["id"]))
                except Exception:
                    pass
            if "src_ip" in item and isinstance(item["src_ip"], str):
                src_ips.add(item["src_ip"].strip())
    return max_id, src_ips


def update_rules_in_row(header: List[str], row: List[str], ip_values: List[str], keep_ids: bool = False) -> Tuple[int, int]:
    """
    Ensure the provided IP list becomes a contiguous block at the very beginning of the rules.
    If keep_ids is False (default), reassign IDs sequentially for all rules so the top block stays first in UIs.
    Returns (added_count, skipped_count)
    """
    try:
        rules_index = header.index("rules")
    except ValueError:
        raise ValueError("CSV header is missing 'rules' column")

    # Parse rules JSON list
    rules_raw = row[rules_index]
    rules_list = parse_json_field(rules_raw)
    if rules_list is None:
        rules_list = []
    if not isinstance(rules_list, list):
        raise ValueError("The 'rules' column does not contain a JSON list")

    # Track existing ids to compute next ids if we keep IDs
    max_id_rules, _ = collect_existing_ids_and_src_ips(rules_list)
    max_id_any = max_id_rules
    try:
        rulesv6_idx = header.index("rulesv6")
        rulesv6_raw = row[rulesv6_idx]
        rulesv6_list = parse_json_field(rulesv6_raw)
        if isinstance(rulesv6_list, list):
            max_id_v6, _ = collect_existing_ids_and_src_ips(rulesv6_list)
            max_id_any = max(max_id_any, max_id_v6)
    except ValueError:
        pass

    # Build contiguous top block
    ip_order: List[str] = [ip.strip() for ip in ip_values if ip.strip()]
    ip_set = set(ip_order)

    # Map first occurrence of src_ip -> rule
    first_seen: Dict[str, Dict[str, Any]] = {}
    for rule in rules_list:
        if isinstance(rule, dict) and isinstance(rule.get("src_ip"), str):
            key = rule["src_ip"].strip()
            if key in ip_set and key not in first_seen:
                first_seen[key] = rule

    added = 0
    skipped = 0

    top_rules: List[Dict[str, Any]] = []
    created_rules: List[Dict[str, Any]] = []

    # Build top block preserving the order of the provided IP list
    for ip in ip_order:
        if ip in first_seen:
            top_rules.append(first_seen[ip])
            skipped += 1  # existed, not newly created
        else:
            # Create new rule; assign temp id, finalized later if needed
            new_rule = build_allow_rule(ip, 0)
            created_rules.append(new_rule)
            top_rules.append(new_rule)
            added += 1

    # Remaining rules: those not in the provided IP set (also remove duplicate occurrences of same ip)
    remaining_rules: List[Dict[str, Any]] = []
    for rule in rules_list:
        if not isinstance(rule, dict):
            remaining_rules.append(rule)
            continue
        key = rule.get("src_ip")
        if isinstance(key, str) and key.strip() in ip_set:
            # skip all occurrences that belong to the top block
            continue
        remaining_rules.append(rule)

    # Concatenate: top block then the rest
    new_rules_list = top_rules + remaining_rules

    if keep_ids:
        # Keep existing rule ids; assign ids only for newly created
        next_id = max_id_any + 1 if max_id_any is not None else 1
        for r in created_rules:
            r["id"] = next_id
            next_id += 1
    else:
        # Reassign ids sequentially so the top block stays visually and logically first
        next_id = 1
        for r in new_rules_list:
            if isinstance(r, dict):
                r["id"] = next_id
                next_id += 1

    row[rules_index] = dump_json_field(new_rules_list)
    return added, skipped


def process(
    csv_path: str,
    ip_txt_path: str,
    output_path: str = None,
    in_place: bool = False,
    make_backup: bool = True,
    keep_ids: bool = False,
) -> Tuple[int, int]:
    header, data_rows = load_csv(csv_path)
    ip_values = read_ip_list(ip_txt_path)

    if not data_rows:
        raise ValueError("CSV has header but no data rows to update")

    # Update only the first row, as QuFirewall export typically has a single policy row
    added_total = 0
    skipped_total = 0
    added, skipped = update_rules_in_row(header, data_rows[0], ip_values, keep_ids=keep_ids)
    added_total += added
    skipped_total += skipped

    # Determine output path
    if in_place:
        if make_backup:
            backup_path = csv_path + ".bak"
            if not os.path.exists(backup_path):
                with open(backup_path, "wb") as bf, open(csv_path, "rb") as of:
                    bf.write(of.read())
        out_path = csv_path
    else:
        if output_path:
            out_path = output_path
        else:
            root, ext = os.path.splitext(csv_path)
            out_path = f"{root}.updated{ext or '.csv'}"

    dump_csv(out_path, header, data_rows)
    return added_total, skipped_total


def interactive_main() -> None:
    print("\n=== QuFirewall 规则置顶工具 ===")
    print("说明：将 IP 列表在规则中置顶为一个连续块，避免干扰原有规则顺序。\n")

    # 输入 CSV 文件路径
    while True:
        csv_path = input("请输入需要处理的 CSV 文件路径（例如：e\\ltsjgo\\QuFirewall_***.csv）：\n> ").strip().strip('"').strip("'")
        if csv_path:
            if os.path.exists(csv_path):
                break
            else:
                print("[错误] 找不到该 CSV 文件，请重新输入。\n")
        else:
            print("[提示] 路径不能为空，请重新输入。\n")

    # 默认的 IP 列表路径为脚本同目录下的 ip_allow_list.txt
    default_ip_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_allow_list.txt")
    ip_prompt = (
        f"请输入 IP 列表 txt 文件路径（回车则使用默认：{default_ip_path}）：\n> "
    )
    ip_path_in = input(ip_prompt).strip().strip('"').strip("'")
    ip_path = ip_path_in or default_ip_path
    if not os.path.exists(ip_path):
        print(f"[错误] 找不到 IP 列表文件：{ip_path}")
        sys.exit(1)

    print("\n请选择操作（输入数字回车）：")
    print("1. 置顶并重排所有规则 ID（生成新文件，推荐先预览）")
    print("2. 置顶但保留现有 ID（生成新文件）")
    print("3. 置顶并重排 ID（原地更新，自动创建 .bak 备份）")
    print("4. 置顶但保留现有 ID（原地更新，自动创建 .bak 备份）")

    choice = input("> ").strip()
    if choice not in {"1", "2", "3", "4"}:
        print("[错误] 无效选择。")
        sys.exit(1)

    keep_ids = choice in {"2", "4"}
    in_place = choice in {"3", "4"}

    # 计算输出路径
    out_path = None
    if not in_place:
        root, ext = os.path.splitext(csv_path)
        suffix = ".updated.top.keepids" if keep_ids else ".updated.top"
        out_path = f"{root}{suffix}{ext or '.csv'}"

    try:
        added, skipped = process(
            csv_path=csv_path,
            ip_txt_path=ip_path,
            output_path=out_path,
            in_place=in_place,
            make_backup=True,
            keep_ids=keep_ids,
        )
        if in_place:
            print(f"\n处理完成：已添加 {added} 条，跳过 {skipped} 条重复。已原地更新并创建备份：{csv_path}.bak")
        else:
            print(f"\n处理完成：已添加 {added} 条，跳过 {skipped} 条重复。已输出到：{out_path}")
    except Exception as e:
        print(f"[错误] 处理失败：{e}")
        sys.exit(1)


def main(argv: List[str]) -> None:
    if not argv:
        # 无参数时进入中文交互模式
        interactive_main()
        return

    parser = argparse.ArgumentParser(
        description="Append/move Allow rules for IP/CIDRs to the very top of QuFirewall CSV export."
    )
    parser.add_argument("--csv", required=True, help="Path to QuFirewall CSV file to update")
    parser.add_argument("--ip", required=True, help="Path to txt file containing IP/CIDR list (one per line)")
    parser.add_argument(
        "--out", default=None, help="Output CSV path (ignored if --in-place is set)"
    )
    parser.add_argument(
        "--in-place", action="store_true", help="Update the CSV in-place (creates .bak unless --no-backup)"
    )
    parser.add_argument(
        "--no-backup", action="store_true", help="Disable .bak backup when using --in-place"
    )
    parser.add_argument(
        "--keep-ids", action="store_true", help="Keep existing rule IDs (only new rules get new IDs). If omitted, all rules are re-numbered so the IP block stays first in UI.")
    args = parser.parse_args(argv)

    try:
        added, skipped = process(
            csv_path=args.csv,
            ip_txt_path=args.ip,
            output_path=args.out,
            in_place=args.in_place,
            make_backup=(not args.no_backup),
            keep_ids=args.keep_ids,
        )
        print(f"Added {added} rules, skipped {skipped} duplicates.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:]) 
    input()