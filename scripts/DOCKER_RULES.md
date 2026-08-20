# Docker Rules

This project uses Docker only for local infrastructure services.

## Managed Services

- `anti-fraud-milvus`: Milvus standalone for `anti_fraud_knowledge`.
- `anti-fraud-mongo`: MongoDB for chat history and risk results.

## Ports

- Milvus SDK/API: `localhost:19530`
- Milvus health/metrics: `localhost:9091`
- MongoDB: `localhost:27017`

Do not run another local Milvus or MongoDB service on these ports at the same time.

## Data Persistence

Docker named volumes are used:

- `anti-fraud-rag_milvus_data`
- `anti-fraud-rag_mongo_data`

`scripts/docker-down.ps1` stops containers but keeps data.
`scripts/docker-clean-data.ps1` deletes the volumes and resets all imported data.

## Commands

Pull images:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/docker-pull.ps1
```

Start:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/docker-up.ps1
```

Stop:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/docker-down.ps1
```

Status:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/docker-status.ps1
```

Restart:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/docker-restart.ps1
```

Reset data:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/docker-clean-data.ps1
```

If image pulling fails with a network `EOF` error, run `docker-pull.ps1` again.
Docker resumes from cached layers in most cases.

## Environment Rules

`.env` should point to local Docker services when using these scripts:

```env
MILVUS_URL=http://localhost:19530
ANTI_FRAUD_COLLECTION=anti_fraud_knowledge
MONGO_URL=mongodb://localhost:27017
MONGO_DB_NAME=anti_fraud_rag
```
