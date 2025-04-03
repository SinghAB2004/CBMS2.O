$PROJECT_ID = "cloud-based-media-storage"
$SERVICE_ACCOUNT = "cbms-storage@${PROJECT_ID}.iam.gserviceaccount.com"
$BUCKET_NAME = "cbms-storage"
$LOCATION = "asia-south1"

# Verify service account exists
Write-Host "Verifying service account..." -ForegroundColor Cyan
gcloud iam service-accounts describe $SERVICE_ACCOUNT

# Verify permissions
Write-Host "`nVerifying IAM roles..." -ForegroundColor Cyan
gcloud projects get-iam-policy $PROJECT_ID `
    --flatten="bindings[].members" `
    --format='table(bindings.role)' `
    --filter="bindings.members:$SERVICE_ACCOUNT"

# Create or verify bucket
Write-Host "`nChecking storage bucket..." -ForegroundColor Cyan
$bucketExists = gcloud storage buckets describe gs://$BUCKET_NAME 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Creating bucket gs://$BUCKET_NAME in $LOCATION..." -ForegroundColor Yellow
    gcloud storage buckets create gs://$BUCKET_NAME `
        --project=$PROJECT_ID `
        --location=$LOCATION `
        --uniform-bucket-level-access

    # Grant service account access to bucket
    Write-Host "Setting bucket permissions..." -ForegroundColor Yellow
    gcloud storage buckets add-iam-policy-binding gs://$BUCKET_NAME `
        --member="serviceAccount:$SERVICE_ACCOUNT" `
        --role="roles/storage.objectAdmin"
} else {
    Write-Host "Bucket gs://$BUCKET_NAME exists" -ForegroundColor Green
}

# Verify final bucket configuration
Write-Host "`nVerifying bucket configuration..." -ForegroundColor Cyan
gcloud storage buckets describe gs://$BUCKET_NAME