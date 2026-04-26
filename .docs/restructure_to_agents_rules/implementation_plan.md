# AIルール構成の最適化と自動化計画

現在のワークスペースを、AIが自動的にルールを認識し、かつ標準的なプロジェクト構成（`.agents/rules/`）に準拠した形に再構築します。

## ユーザーレビューが必要な事項
- `README.md` はルートに保持し、内容を「クローンするだけでルールが適用される」という説明に更新します。
- ルール本体（`global_rules.md`, `code_style_guide.md`）は `.agents/rules/` 内に移動します。
- `.git` と `.gitignore` は現在のルートに維持し、プロジェクト全体を管理します。

## 提案される変更

### [ディレクトリ構成の変更]

#### [MOVE] `global_rules.md` -> `.agents/rules/global_rules.md`
#### [MOVE] `code_style_guide.md` -> `.agents/rules/code_style_guide.md`
#### [MODIFY] `README.md` (ルートに維持し、構成に合わせて更新)

### [自動化設定]
- `README.md` に、AIがこのパスを自動参照する旨を記載。
- 必要に応じて、AI向けの認識用指示をルートに追加。

## 検証計画

### 手動確認
- `ls -R` でファイル配置を確認。
- AIに対し、「現在のワークスペースにあるルールを説明して」と問いかけ、正しく `.agents/rules/` 内の内容を読み取っているか確認。
