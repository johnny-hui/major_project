"""
Description:
This Python file defines functions that use the DeepFace library
for facial recognition.

@see Source 1:
    https://viso.ai/computer-vision/deepface/

@see Source 2:
    https://github.com/serengil/deepface

"""
import os
from deepface import DeepFace
from models.Blockchain import Blockchain
from models.Transaction import Transaction
from utility.general.utils import create_temp_file_from_bytes


def verify_image(ref_img_path: str, img_bytes: bytes):
    """
    Uses the DeepFace library to perform facial recognition on two images.

    @param ref_img_path:
        A string for the reference image path

    @param img_bytes:
        Bytes containing the second image

    @return: Boolean (T/F)
        True if the two facial images are similar, False otherwise
    """
    temp_img_path = create_temp_file_from_bytes(data=img_bytes)
    result = DeepFace.verify(ref_img_path, temp_img_path, enforce_detection=False)
    os.remove(temp_img_path)  # => cleanup
    return result["verified"]


def perform_facial_recognition_on_peer(blockchain: Blockchain, request: Transaction):
    """
    Performs facial recognition (using DeepFace) on a peer based
    on the image submitted from their connection request and the
    images stored in previous blocks.

    @param blockchain:
        A Blockchain object

    @param request:
        A Transaction object

    @return: None
    """
    if blockchain is not None:
        # Get all blocks from requesting peer's IP
        block_list = blockchain.get_blocks_from_ip(ip=request.ip_addr, return_all=True)

        if block_list is not None:  # => If blocks present from requesting peer
            reference_image_path = create_temp_file_from_bytes(data=request.image)  # to be compared against block images

            # Run Deepface (one block at a time)
            results = []
            for block in block_list:
                results.append(verify_image(reference_image_path, block.image))

            # # Run Facial Recognition (DeepFace) in parallel (using multiple CPU cores)
            # args_list = [(reference_image_path, block.image) for block in block_list]
            # results = start_parallel_operation(task=verify_image,
            #                                    task_args=args_list,
            #                                    num_processes=len(block_list),
            #                                    prompt=FACIAL_RECOGNITION_PROMPT)

            # Calculate the accuracy
            correct_matches = sum(results)
            total_images = len(results)
            accuracy = (correct_matches / total_images) * 100 if total_images > 0 else 0

            # Output the results and perform cleanup
            print(f"[+] Number of Correct Matches: {correct_matches}/{total_images}")
            print(f"[+] Image Integrity (%): {accuracy:.2f}%")
            if accuracy == 0:
                print("[+] VERIFICATION WARNING: The peer's provided facial image does not match any block records!")
            elif accuracy == 50:
                print("[+] VERIFICATION WARNING: The peer's provided facial image matches half of the block records!")
            elif accuracy == 100:
                print("[+] VERIFICATION PASSED: The peer's provided facial image matches all block records!")
            elif accuracy > 75:
                print("[+] VERIFICATION PASSED: The peer's provided facial image matches most of the block records!")
            else:
                print("[+] VERIFICATION WARNING: The peer's provided facial image matches less than 75% of block records!")
            os.remove(reference_image_path)
        else:
            print("[+] VERIFICATION WARNING: Cannot perform facial recognition on requesting peer's image! "
                  "[REASON: No existing block can be found]")
