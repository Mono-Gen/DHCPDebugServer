# コードドキュメントルール (Code Documentation Rules)

このルールは「AIが後からコードを読んだとき、ユーザーへの質問なしに意図を正確に理解できる状態」を目標とします。

## 0. ソースコード内の言語ルール
ソースコード内の以下の要素は**すべて英語で記述**すること。
- Docstring（関数・クラス・モジュールの説明）
- コメント（インラインコメント含む）
- 定数名・変数名・関数名・クラス名
- TODO / FIXME / NOTE / HACK タグのメッセージ

**理由**: 英語はAIにとってトークン消費が少なく（日本語の約1/2）、解釈精度も高いため。
ユーザーへの回答・ドキュメント（README・task.md等）は引き続き日本語で行う。

## 1. モジュール（ファイル）の先頭コメント
各ソースファイルの先頭に、そのファイルの目的・対象機器・プロトコルを記載すること。

```python
"""
AHM-64 IP Control Module

Device: Yamaha AHM-64
Protocol: AHM Serial MIDI over TCP (Port 49280)
Reference: AHM-64 Reference Manual Rev.3.0 - Section 7 (IP Control)

This module manages command transmission, tally reception, and state synchronization.
"""
```

## 2. 関数・メソッドのDocstring（必須）
全ての関数・メソッドに以下の形式でDocstringを記述すること。
特に「なぜその値なのか」「なぜその処理をするのか」の背景を必ず記載すること。

```python
def send_fader_level(channel: int, level: float, timeout: float = 0.5) -> bool:
    """
    Sends the fader level for a specific channel.

    After sending the command, it waits for a Tally (ACK) from the device.
    Returns True only if the Tally is received successfully.
    If Tally is not received, returns False, and the caller should rollback the UI state.

    Args:
        channel (int): Channel number (1-64). Raises ValueError if out of spec.
        level (float): Fader level (0.0 to 1.0). 0.0 is mute, 1.0 is +10dB.
        timeout (float): Timeout in seconds for Tally wait. Based on AHM-64 specs.

    Returns:
        bool: True if Tally received, False if timeout or error.

    Raises:
        ValueError: If channel is out of range (1-64).
        ConnectionError: If the socket connection is lost.
    """
```

## 3. 型ヒントの必須化
全ての引数・戻り値に型ヒントを付けること。
型ヒントはAIがコードを読む際に「この変数に何が入るか」を推測なしに把握するために不可欠です。

```python
# ❌ Bad: AI has to guess what's inside
def process(data, mode, flag):
    pass

# ✅ Good: AI can immediately identify types
def process(data: bytes, mode: str, flag: bool = True) -> dict:
    pass
```

## 4. マジックナンバー・マジックバイトの禁止
数値やバイト列をそのまま書かず、必ず名前付き定数として定義し、
その意味・出典（マニュアルのページ数等）をコメントで記載すること。

```python
# ❌ Bad: Meaning of 0x42 is unclear
if response[2] == 0x42:
    pass

# ✅ Good: Meaning and source are clear
# AHM-64 Reference Manual Rev.3.0, Section 7.3, Table 7-2
# 0x42 = ACK (Success) Byte
AHM_TALLY_ACK = 0x42

if response[2] == AHM_TALLY_ACK:
    pass
```

## 5. 「なぜ」を説明するコメントの義務化
「何をしているか」はコードを読めば分かる。コメントには「なぜそうしているか」を記載すること。
特にハードウェア仕様に起因する処理、タイムアウト値、待機処理には必ず理由を書くこと。

```python
# ❌ Bad: Only says what the code does
time.sleep(0.1)  # Sleep for 0.1s

# ✅ Good: Explains WHY the sleep is necessary
# AHM-64 may fail to process commands if sent too rapidly.
# Per Manual Section 7.2, maintain at least 100ms interval between commands.
time.sleep(0.1)
```

## 6. 未解決事項・既知の問題のマーキング
修正が必要な箇所・仕様が不明な箇所・暫定的な実装には必ず以下のタグでマークすること。
AIが後からコードを読んだ際に、暫定的な実装と確定的な実装を区別できるようにするため。

```python
# TODO: Need manufacturer confirmation for dB conversion formula. Currently using linear.
# FIXME: Socket may not clear correctly after reconnection (investigating)
# NOTE: This timeout (200ms) is specific to AHM-64.
# HACK: Need to send this command twice due to device firmware bug (as of v2.1.3)
```

## 7. クラスの責任の明示
クラスには「何の責任を持つか」「何の責任を持たないか」を明記すること。

```python
class AHMController:
    """
    Class to manage communication with AHM-64.

    Responsibilities:
    - Manage TCP socket connection/reconnection
    - Map commands to Tally responses
    - Maintain device state cache

    Out of Scope (Caller should handle):
    - UI updates (use callbacks for state changes)
    - Notifying errors to the user
    """
```
