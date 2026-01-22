package org.multipaz.compose.prompt

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.unit.Dp
import coil3.ImageLoader
import org.multipaz.prompt.ConsentPromptDialogModel
import org.multipaz.prompt.PassphrasePromptDialogModel
import org.multipaz.prompt.PromptDialogModel
import org.multipaz.prompt.PromptModel
import org.multipaz.prompt.WebPromptModel

@Composable
actual fun PromptDialogs(
    promptModel: PromptModel,
    imageLoader: ImageLoader?,
    maxHeight: Dp?,
    excludeTypes: List<PromptDialogModel.DialogType<*>>
) {
    val model = promptModel as WebPromptModel

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