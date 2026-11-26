//! The shared `Reader`: reads in order, bounds, and canonical encodings.

use alloc::vec::Vec;

use crate::Error;
use crate::backend::{Backend, ORDER, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar};
use crate::encoding::Reader;

fn point_bytes<B: Backend>(k: u64) -> [u8; POINT_LENGTH] {
    B::Point::mul_generator(&B::Scalar::from(k))
        .to_bytes()
        .unwrap()
}

fn reads_in_order<B: Backend>() {
    let scalar = B::Scalar::from(5).to_bytes();
    let points = [7, 8, 9].map(point_bytes::<B>);
    let mut bytes = alloc::vec![0xa5, 0x5a, 0x01];
    bytes.extend_from_slice(&scalar);
    bytes.extend_from_slice(points.as_flattened());

    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.take(0).unwrap(), &[] as &[u8]);
    assert_eq!(reader.take(2).unwrap(), &[0xa5, 0x5a]);
    assert_eq!(reader.array::<1>().unwrap(), &[0x01]);
    assert_eq!(reader.scalar::<B>().unwrap().to_bytes(), scalar);
    assert_eq!(reader.point::<B>().unwrap().to_bytes(), Some(points[0]));
    let rest: Vec<_> = reader
        .points::<B>(2)
        .unwrap()
        .iter()
        .map(|point| point.to_bytes().unwrap())
        .collect();
    assert_eq!(rest, points[1..]);
    reader.finish().unwrap();
}

#[test]
fn reads_stay_in_bounds() {
    let bytes = [1, 2, 3];

    // A read past the end fails and consumes nothing.
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.take(4).unwrap_err(), Error::Deserialize);
    assert_eq!(reader.array::<4>().unwrap_err(), Error::Deserialize);
    assert_eq!(reader.take(3).unwrap(), &bytes);
    assert_eq!(reader.take(1).unwrap_err(), Error::Deserialize);
    reader.finish().unwrap();

    // Nor does a length that overflows the offset wrap around.
    let mut reader = Reader::new(&bytes);
    reader.take(1).unwrap();
    assert_eq!(reader.take(usize::MAX).unwrap_err(), Error::Deserialize);
    assert_eq!(reader.take(2).unwrap(), &bytes[1..]);

    // Unread bytes fail `finish`, at any offset.
    Reader::new(&[]).finish().unwrap();
    assert_eq!(
        Reader::new(&bytes).finish().unwrap_err(),
        Error::Deserialize
    );
    let mut reader = Reader::new(&bytes);
    reader.take(2).unwrap();
    assert_eq!(reader.finish().unwrap_err(), Error::Deserialize);
}

fn only_canonical_encodings_decode<B: Backend>() {
    // The identity has no encoding, and a point's length is exact.
    let point = point_bytes::<B>(7);
    assert_eq!(
        Reader::new(&[0; POINT_LENGTH]).point::<B>().unwrap_err(),
        Error::Deserialize
    );
    assert_eq!(
        Reader::new(&point[..POINT_LENGTH - 1])
            .point::<B>()
            .unwrap_err(),
        Error::Deserialize
    );

    // A scalar is below the order.
    let mut below = ORDER;
    below[SCALAR_LENGTH - 1] -= 1;
    assert_eq!(Reader::new(&below).scalar::<B>().unwrap().to_bytes(), below);
    assert_eq!(
        Reader::new(&ORDER).scalar::<B>().unwrap_err(),
        Error::Deserialize
    );
    assert_eq!(
        Reader::new(&below[..SCALAR_LENGTH - 1])
            .scalar::<B>()
            .unwrap_err(),
        Error::Deserialize
    );

    // A vector of points reads exactly `count` of them, and fails on any
    // that does not decode.
    let mut bytes = [point, point].concat();
    let mut reader = Reader::new(&bytes);
    assert!(reader.points::<B>(0).unwrap().is_empty());
    assert_eq!(reader.points::<B>(1).unwrap().len(), 1);
    assert_eq!(reader.points::<B>(2).unwrap_err(), Error::Deserialize);
    bytes[POINT_LENGTH..].fill(0);
    assert_eq!(
        Reader::new(&bytes).points::<B>(2).unwrap_err(),
        Error::Deserialize
    );
}

backend_tests!(reads_in_order, only_canonical_encodings_decode);
