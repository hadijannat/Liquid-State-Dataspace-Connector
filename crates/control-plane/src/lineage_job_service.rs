use crate::execution_pipeline::{BatchLineageRequest, BatchLineageResult, ExecutionPipeline};
use lsdc_common::error::Result;

pub struct LineageJobService {
    pipeline: ExecutionPipeline,
}

impl LineageJobService {
    pub fn new(pipeline: ExecutionPipeline) -> Self {
        Self { pipeline }
    }

    pub async fn run_batch_csv_lineage(
        &self,
        request: BatchLineageRequest,
    ) -> Result<BatchLineageResult> {
        self.pipeline.run_batch_csv_lineage(request).await
    }

    pub fn pipeline(&self) -> &ExecutionPipeline {
        &self.pipeline
    }
}
