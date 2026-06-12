use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

const SLICE_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

pub struct SliceBody {
    bytes: Bytes,
    pos: usize,
}

impl SliceBody {
    pub fn new(bytes: Bytes) -> Self {
        Self { bytes, pos: 0 }
    }
}

impl Clone for SliceBody {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes.clone(), pos: 0 }
    }
}

impl Body for SliceBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.pos >= this.bytes.len() {
            return Poll::Ready(None);
        }
        let end = std::cmp::min(this.pos + SLICE_CHUNK_SIZE, this.bytes.len());
        let chunk = this.bytes.slice(this.pos..end);
        this.pos = end;
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact((self.bytes.len().saturating_sub(self.pos)) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn collect_frame_sizes(mut body: SliceBody) -> (Vec<usize>, Bytes) {
        let mut sizes = Vec::new();
        let mut all = Vec::new();
        while let Some(Ok(frame)) = body.frame().await {
            if let Some(data) = frame.data_ref() {
                sizes.push(data.len());
                all.extend_from_slice(data);
            }
        }
        (sizes, Bytes::from(all))
    }

    #[tokio::test]
    async fn non_aligned_size_yields_correct_frames() {
        let data = Bytes::from(vec![0xABu8; 2_621_440]); // 2.5 MiB
        let body = SliceBody::new(data.clone());
        assert_eq!(body.size_hint().exact(), Some(2_621_440));

        let (sizes, collected) = collect_frame_sizes(body).await;
        assert_eq!(sizes, vec![1_048_576, 1_048_576, 524_288]);
        assert_eq!(collected, data);
    }

    #[tokio::test]
    async fn exact_multiple_yields_full_frames() {
        let data = Bytes::from(vec![0xCDu8; 2_097_152]); // 2 MiB
        let (sizes, collected) = collect_frame_sizes(SliceBody::new(data.clone())).await;
        assert_eq!(sizes, vec![1_048_576, 1_048_576]);
        assert_eq!(collected, data);
    }

    #[tokio::test]
    async fn single_byte_yields_one_frame() {
        let data = Bytes::from(vec![0xFFu8; 1]);
        let body = SliceBody::new(data.clone());
        assert_eq!(body.size_hint().exact(), Some(1));

        let (sizes, collected) = collect_frame_sizes(body).await;
        assert_eq!(sizes, vec![1]);
        assert_eq!(collected, data);
    }

    #[tokio::test]
    async fn empty_body_yields_no_frames() {
        let body = SliceBody::new(Bytes::new());
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));

        let (sizes, _) = collect_frame_sizes(body).await;
        assert!(sizes.is_empty());
    }

    #[tokio::test]
    async fn clone_resets_pos_to_zero() {
        let data = Bytes::from(vec![0xAAu8; 2_097_152]); // 2 MiB
        let mut original = SliceBody::new(data);

        // Consume original fully
        let _ = original.frame().await; // read first frame
        let _ = original.frame().await; // read second frame
        assert!(original.is_end_stream());

        let cloned = original.clone();
        assert!(!cloned.is_end_stream());
        assert_eq!(cloned.size_hint().exact(), Some(2_097_152));

        let (sizes, _) = collect_frame_sizes(cloned).await;
        assert_eq!(sizes, vec![1_048_576, 1_048_576]);
    }
}
