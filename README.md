# AI Rules Template

このリポジトリは、AIアシスタントを使用した開発プロジェクトで共通して使用する「開発ルール」をまとめたテンプレートです。

## 特徴
- **自動認識**: ルールは `.agents/rules/` に配置されており、対応するAI（Antigravity等）はこのリポジトリをクローンするだけで自動的にルールを認識・適用します。
- **標準構成**: 多くのAI開発プロジェクトで推奨されるディレクトリ構成を採用しています。

## 構成
- `.agents/rules/global_rules.md`: 基本的な回答方針、ドキュメント管理、セキュリティ、プライバシーに関するルール。
- `.agents/rules/code_style_guide.md`: コードの品質、スタイル、GitHub利用、開発プロセスに関する詳細なルール。
- `.agents/rules/device_control_rules.md`: ハードウェア制御、通信アーキテクチャ、状態同期に関する特化ルール。
- `.agents/rules/ui_ux_rules.md`: 機器制御UI、状態の視覚的表現、Stream Deck・専用コントローラー向けデザインルール。
- `.agents/rules/resource_management_rules.md`: メモリ・スレッド・ソケット等のシステムリソース管理、マルチキャストJoin/Leave、ネットワークリソース管理のルール。
- `.agents/rules/documentation_rules.md`: AIが後からコードを読んでも意図を正確に理解できるための、Docstring・型ヒント・コメント・定数定義に関するルール。

## 使い方
1. このリポジトリをプロジェクトのルートにクローンします。
2. AIは自動的に `.agents/rules/` 内のルールを読み込み、開発をサポートします。
3. **プロジェクト別設定**: プロジェクトのルートに `.agents/config.md` を作成し、適用したいルールファイルを記述することで、AIの読み込み負荷を下げ、精度を高めることができます。
   ```markdown
   # Project Rules Configuration
   This project applies the following rules:
   - .agents/rules/global_rules.md
   - .agents/rules/code_style_guide.md
   - .agents/rules/device_control_rules.md
   ```
4. プロジェクト固有のルールが必要な場合は、`.agents/rules/` 内にファイルを追加してください。

## ルールの保守と更新
- **定期的見直し**: ルールは「一度作ったら終わり」ではなく、実際の開発で得られた知見（「この書き方の方がバグが少なかった」「このプロトコルには例外があった」等）を反映し、常に最新の状態に更新してください。
- **AIへのフィードバック**: AIがルールに違反した場合は、その場で指摘すると同時に、必要であればルール自体の記述を改善してください。

## セキュリティ
- **絶対パスの禁止** や **機密情報のハードコード禁止** など、セキュリティに関する項目は常に最新の状態に保ち、厳守してください。
