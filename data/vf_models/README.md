# Visual Forensics model assets

These files are the classic OpenCV Haar-cascade classifiers used by the Visual
Forensics face/eye detector in `vf_image.py`.

| File | Purpose | Size |
|---|---|---|
| `haarcascade_frontalface_default.xml` | Frontal-face detection | ~908 KB |
| `haarcascade_eye.xml` | Eye-region detection inside a face | ~333 KB |
| `haarcascade_profileface.xml` | Profile-face detection (optional) | ~809 KB |

## Provenance and licensing

- Source: the OpenCV project's `data/haarcascades` directory
  (`https://github.com/opencv/opencv/tree/4.x/data/haarcascades`).
- The OpenCV cascade data files are distributed under the Apache License 2.0
  (see the OpenCV repository `LICENSE` and `data/` notes). They are small,
  CPU-only, and require no GPU.

## Storage, hardware and performance

- Total on-disk footprint is under 2.5 MB.
- Detection runs on CPU with no additional runtime download.
- Typical cost is well under one second per image at moderate resolutions;
  `vf_image.detect_faces_and_eyes` downsamples large images before detection.

## What these models do and do not do

- They perform **shape detection only**. They do not recognise, verify, or
  identify people, and they must never be used as identity evidence.
- They are sensitive to head pose, occlusion, glasses, lighting and resolution.
  Non-frontal or low-resolution faces are frequently missed. A missed detection
  means "not detected by this model", not "no face present".
- If OpenCV (or its cascade API) is unavailable at runtime, the tool reports
  face/eye analysis as an **unsupported capability** rather than fabricating a
  result. See `data/vf_models/` detection helpers in `vf_image.py`.
