package org.multipaz.compose.prompt

import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.Dp
import coil3.ImageLoader
import org.multipaz.compose.branding.Branding
import org.multipaz.prompt.AndroidPromptModel
import org.multipaz.prompt.BiometricPromptDialogModel
import org.multipaz.prompt.ConsentPromptDialogModel
import org.multipaz.prompt.PassphrasePromptDialogModel
import org.multipaz.prompt.PromptDialogModel
import org.multipaz.prompt.PromptModel
import org.multipaz.prompt.ScanNfcPromptDialogModel

@Composable
actual fun PromptDialogs(
    promptModel: PromptModel,
    imageLoader: ImageLoader?,
    maxHeight: Dp?,
    excludeTypes: List<PromptDialogModel.DialogType<*>>
) {
    val model = promptModel as AndroidPromptModel

    if (!excludeTypes.contains(ScanNfcPromptDialogModel.DialogType)) {
        ScanNfcTagPromptDialog(model.getDialogModel(ScanNfcPromptDialogModel.DialogType))
    }
    if (!excludeTypes.contains(BiometricPromptDialogModel.DialogType)) {
        BiometricPromptDialog(model.getDialogModel(BiometricPromptDialogModel.DialogType))
    }
    if (!excludeTypes.contains(PassphrasePromptDialogModel.DialogType)) {
        PassphrasePromptDialog(model.getDialogModel(PassphrasePromptDialogModel.DialogType))
    }
    if (!excludeTypes.contains(ConsentPromptDialogModel.DialogType)) {
        ConsentPromptDialog(
            model = model.getDialogModel(ConsentPromptDialogModel.DialogType),
            imageLoader = imageLoader,
            maxHeight = maxHeight
        )
    }
}