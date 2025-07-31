package org.multipaz.testapp.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.multipaz.testapp.TestAppSettingsModel
import org.multipaz.testapp.TestAppSettingsModel.RoutingOption

@Composable
actual fun NfcRoutingChoice(settingsModel: TestAppSettingsModel, modifier: Modifier) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            "NFC Routing:",
            style = MaterialTheme.typography.titleMedium
        )
        CompactTwoButtonsWidget(
            option1Text = "Host",
            option1Value = RoutingOption.HOST,
            option2Text = "SE",
            option2Value = RoutingOption.SE,
            onOptionSelected = { selected ->
                settingsModel.selectNfcRoutingDestination(selected)
            }
        )
    }
}

/** Common compact composable row item displaying two named Radio Buttons in a single row after the description.
 *
 * @param modifier The modifier to be applied to the composable.
 * @param option1Text The text of the first option.
 * @param option1Value The value of the first option.
 * @param option2Text The text of the second option.
 * @param option2Value The value of the second option.
 * @param onOptionSelected A callback to be invoked when a new option is selected.
 * @param enabled Whether the composable is enabled for interaction.
 */
@Composable
private fun <T> CompactTwoButtonsWidget(
    modifier: Modifier = Modifier,
    option1Text: String,
    option1Value: T,
    option2Text: String,
    option2Value: T,
    onOptionSelected: (selection: T) -> Unit,
    enabled: Boolean = true
) {

    Row(
        modifier = modifier.wrapContentWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // Option 1
        Button(
            onClick = { if (enabled) onOptionSelected(option1Value) },
            enabled = enabled,
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 4.dp)
        ) {
            Text(
                text = option1Text,
                style = MaterialTheme.typography.bodyLarge,
            )
        }

        // Option 2
        Button(
            onClick = { if (enabled) onOptionSelected(option2Value) },
            enabled = enabled,
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 4.dp)
        ) {
            Text(
                text = option2Text,
                style = MaterialTheme.typography.bodyLarge,
            )
        }
    }
}